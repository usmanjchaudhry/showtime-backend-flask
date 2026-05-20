# routes/auth.py
import os
import io
import textwrap
import base64
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, g
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.utils import ImageReader

# ✅ Import the shared tools we just built in core.py
from core import sb_admin, sb_public, err, log, auth_required, WAIVER_BUCKET

auth_bp = Blueprint('auth', __name__)

# ────────────────────────── storage helpers ──────────────────────────
def ensure_bucket(name: str):
    try:
        buckets = sb_admin.storage.list_buckets()
        if not any(b.get("name") == name for b in buckets):
            log.info(f"[storage] creating bucket {name}")
            sb_admin.storage.create_bucket(name, public=True)
    except Exception as e:
        log.warning(f"[storage] ensure bucket failed: {e}")

def parse_data_url_png(data_url: str) -> bytes:
    if not data_url or not data_url.startswith("data:image"):
        return b""
    header, b64 = data_url.split(",", 1)
    return base64.b64decode(b64)

# ────────────────────────── pdf generation ──────────────────────────
def build_waiver_pdf(waiver, full_name, dob_str, signed_at_dt, ip, ua, sig_png_bytes: bytes) -> bytes:
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    width, height = letter
    margin = 0.75 * inch
    x = margin
    y = height - margin

    c.setFont("Helvetica-Bold", 14)
    c.drawString(x, y, waiver["title"])
    y -= 0.3 * inch

    c.setFont("Helvetica", 9)
    hdr = f"Waiver slug: {waiver['slug']} • version: {waiver['version']} • hash: {waiver['hash']}"
    c.drawString(x, y, hdr)
    y -= 0.25 * inch

    c.setFont("Helvetica", 10)
    for line in textwrap.wrap(waiver["body"], width=95):
        if y < 1.8 * inch:
            c.showPage()
            y = height - margin
            c.setFont("Helvetica", 10)
        c.drawString(x, y, line)
        y -= 12

    if y < 2.2 * inch:
        c.showPage()
        y = height - margin

    c.setFont("Helvetica-Bold", 11)
    c.drawString(x, y, "Signature")
    y -= 0.18 * inch
    c.setFont("Helvetica", 10)
    meta = [
        f"Signed by: {full_name}",
        f"DOB: {dob_str or '—'}",
        f"Signed at (UTC): {signed_at_dt.isoformat()}",
        f"IP: {ip or '—'}",
        f"User Agent: {ua[:200] if ua else '—'}",
    ]
    for m in meta:
        c.drawString(x, y, m)
        y -= 12

    if sig_png_bytes:
        try:
            img = ImageReader(io.BytesIO(sig_png_bytes))
            c.drawImage(img, x, y - 1.1 * inch, width=3.5 * inch, height=1.1 * inch, mask="auto")
        except Exception as e:
            log.warning(f"[pdf] embed signature failed: {e}")
    y -= 1.3 * inch

    c.showPage()
    c.save()
    buf.seek(0)
    return buf.read()

# ───────────────────────── signup/login ────────────────────────────
@auth_bp.post("/signup")
def signup():
    body = request.get_json(force=True, silent=True) or {}
    email = body.get("email")
    password = body.get("password")
    if not email or not password:
        return err("email and password required", 400)

    try:
        res = sb_admin.auth.admin.create_user({"email": email, "password": password, "email_confirm": True})
        uid = res.user.id
        log.info(f"[{getattr(g, '_rid', '-')}] created auth user {uid}")
    except Exception as e:
        return err(f"auth create failed: {e}", 400)

    profile = {
        "user_id": uid,
        "email": email,
        "first_name": body.get("first_name"),
        "last_name": body.get("last_name"),
        "phone": body.get("phone"),
        "birthday": body.get("birthday"),
        "is_admin": False,
        "signed_waiver": False,
    }
    try:
        sb_admin.table("user_profiles").upsert(profile).execute()
    except Exception as e:
        try: sb_admin.auth.admin.delete_user(uid)
        except Exception: pass
        return err(f"profile insert failed: {e}", 500)

    return {"user_id": uid}, 201

@auth_bp.post("/login")
def login():
    body = request.get_json(force=True, silent=True) or {}
    email = body.get("email")
    password = body.get("password")
    if not email or not password:
        return err("email and password required", 400)

    try:
        res = sb_public.auth.sign_in_with_password({"email": email, "password": password})
        session = res.session
        return {
            "access_token": session.access_token,
            "refresh_token": session.refresh_token,
            "user_id": res.user.id,
            "expires_in": session.expires_in,
            "token_type": session.token_type,
        }, 200
    except Exception as e:
        return err(f"invalid login: {e}", 401)

@auth_bp.post("/api/auth/refresh")
def auth_refresh():
    body = request.get_json(force=True, silent=True) or {}
    refresh_token = (body.get("refresh_token") or "").strip()
    if not refresh_token: return err("refresh_token required", 400)

    try:
        res = sb_public.auth.refresh_session(refresh_token)
        session = res.session
        return jsonify({
            "access_token": session.access_token,
            "refresh_token": session.refresh_token,
            "user_id": res.user.id,
            "expires_in": session.expires_in,
            "token_type": session.token_type,
        })
    except Exception as e:
        return err(f"refresh failed: {e}", 401)


# ───────────────────────── profile updates ────────────────────────────
@auth_bp.get("/api/profile/me")
@auth_required
def profile_me():
    rows = sb_admin.table("user_profiles").select("*").eq("user_id", g.user_id).limit(1).execute().data
    if not rows: return err("profile not found", 404)
    return jsonify(rows[0])

@auth_bp.post("/api/user/update-phone")
@auth_required
def update_phone():
    rid = getattr(g, "_rid", "-")
    body = request.get_json(force=True, silent=True) or {}
    
    user_id = body.get('user_id')
    phone = body.get('phone')
    sms_consent = body.get('sms_consent', False)

    if not user_id or not phone: return err("Missing user ID or phone number", 400)
    if user_id != g.user_id: return err("Forbidden: Cannot update another user's profile", 403)

    try:
        update_data = {'phone': phone}
        if sms_consent:
            update_data['sms_consent'] = True
            update_data['sms_consent_at'] = datetime.now(timezone.utc).isoformat()

        sb_admin.table('user_profiles').update(update_data).eq('user_id', user_id).execute()

        # We will handle the Mailchimp sync step later using the Admin Blueprint 
        # to prevent cross-imports here.

        log.info(f"[{rid}] Phone & consent updated successfully for {user_id}")
        return jsonify({"status": "success", "phone": phone}), 200
    except Exception as e:
        log.error(f"[{rid}] Error updating phone: {e}")
        return err(f"Failed to update phone: {e}", 500)


# ───────────────────────── waivers ────────────────────────────
@auth_bp.get("/api/waivers/active")
@auth_required
def waiver_active():
    subject_type = (request.args.get("subjectType") or "user").lower()
    subject_id = request.args.get("subjectId")
    if subject_type == "user": subject_id = g.user_id

    waivers = sb_admin.table("waivers").select("id,slug,version,title,hash,is_active,required_for_purchase").eq("is_active", True).eq("required_for_purchase", True).limit(1).execute().data
    if not waivers: return jsonify({"waiver": None, "signed": False})

    w = waivers[0]
    q = sb_admin.table("waiver_signatures").select("id").eq("waiver_id", w["id"]).eq("waiver_version", w["version"]).is_("revoked_at", "null")
    q = q.eq("subject_user_id", subject_id) if subject_type == "user" else q.eq("dependent_id", subject_id)
    signed = bool(q.limit(2).execute().data)

    return jsonify({"waiver": w, "signed": signed})

@auth_bp.post("/api/waivers/sign")
@auth_required
def waiver_sign():
    body = request.get_json(force=True, silent=True) or {}
    subject_type = (body.get("subject_type") or "user").lower()
    subject_id = g.user_id if subject_type == "user" else body.get("subject_id")

    waivers = sb_admin.table("waivers").select("*").eq("is_active", True).eq("required_for_purchase", True).limit(1).execute().data
    if not waivers: return err("no active waiver to sign", 400)
    w = waivers[0]

    sig_png_bytes = parse_data_url_png(body.get("signature_data_url"))
    
    payload = {
        "waiver_id": w["id"], "waiver_version": w["version"], "signed_by_user_id": g.user_id,
        "relationship_to_subject": body.get("relationship_to_subject"), "full_name": body.get("full_name"),
        "date_of_birth": body.get("date_of_birth"), "signature_svg": body.get("signature_svg"),
        "ip_address": request.remote_addr, "user_agent": request.headers.get("User-Agent"),
    }
    if subject_type == "user": payload["subject_user_id"] = subject_id
    else: payload["dependent_id"] = subject_id

    try:
        sig = sb_admin.table("waiver_signatures").insert(payload).execute().data[0]
        sig_id = sig["id"]
    except Exception as e:
        return err(f"sign insert failed: {e}", 400)

    ensure_bucket(WAIVER_BUCKET)
    signed_at = datetime.now(timezone.utc)

    try:
        sig_url = None
        if sig_png_bytes:
            sig_path = f"signatures/{sig_id}.png"
            sb_admin.storage.from_(WAIVER_BUCKET).upload(sig_path, sig_png_bytes, {"content-type": "image/png", "upsert": True})
            sig_url = sb_admin.storage.from_(WAIVER_BUCKET).get_public_url(sig_path).get("publicURL")

        pdf_bytes = build_waiver_pdf(w, payload["full_name"] or "", payload["date_of_birth"] or "", signed_at, payload["ip_address"], payload["user_agent"], sig_png_bytes)
        pdf_path = f"pdf/{sig_id}.pdf"
        sb_admin.storage.from_(WAIVER_BUCKET).upload(pdf_path, pdf_bytes, {"content-type": "application/pdf", "upsert": True})
        pdf_url = sb_admin.storage.from_(WAIVER_BUCKET).get_public_url(pdf_path).get("publicURL")

        sig = sb_admin.table("waiver_signatures").update({"signature_image_url": sig_url, "pdf_url": pdf_url}).eq("id", sig_id).execute().data[0]
    except Exception as e:
        log.warning(f"asset upload failed: {e}")

    if subject_type == "user":
        try: sb_admin.table("user_profiles").update({"signed_waiver": True}).eq("user_id", subject_id).execute()
        except Exception: pass

    return jsonify(sig), 201