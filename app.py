# app.py (rewritten + updated for subscription & one-time payments)
import os
import json
import logging
import hashlib
import traceback
import hmac
import base64
import time
import calendar
from uuid import uuid4
from time import perf_counter
from datetime import datetime, timezone, timedelta
from typing import Dict, List

from flask import Flask, jsonify, request, make_response, g
from dotenv import load_dotenv
from flask_cors import CORS
from functools import wraps

import stripe

from supabase import create_client, Client
from supabase.lib.client_options import ClientOptions
import io, textwrap
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.utils import ImageReader

WAIVER_BUCKET = os.getenv("WAIVER_BUCKET", "waivers")

# ────────────────────────── env / clients ──────────────────────────
load_dotenv()

SUPABASE_URL = os.environ["SUPABASE_URL"]
SERVICE_KEY = os.environ["SUPABASE_SERVICE_ROLE"]
ANON_KEY = os.getenv("SUPABASE_ANON")

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")
STRIPE_PRICE_ID_MONTHLY = os.getenv("STRIPE_PRICE_ID_MONTHLY")  # optional seed helper
ENABLE_DEV_ROUTES = os.getenv("ENABLE_DEV_ROUTES", "0") == "1"

# Optional: enable QR flow by setting this
CHECKIN_QR_SECRET = os.getenv("CHECKIN_QR_SECRET")

stripe.api_key = STRIPE_SECRET_KEY

# Supabase admin + public clients
sb_admin: Client = create_client(
    SUPABASE_URL,
    SERVICE_KEY,
    options=ClientOptions(auto_refresh_token=False, persist_session=False),
)
sb_public: Client = create_client(
    SUPABASE_URL,
    ANON_KEY or SERVICE_KEY,
    options=ClientOptions(auto_refresh_token=False, persist_session=False),
)

# ────────────────────────── logging setup ──────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("api")

# ────────────────────────── flask + cors ───────────────────────────
app = Flask(__name__)
CORS_ORIGINS = ["http://localhost:3000", "http://localhost:5173"]
CORS(
    app,
    resources={r"/(signup|login|api/.*|ping|dev/.*|debug/.*)": {"origins": CORS_ORIGINS}},
)

def err(msg, code=400):
    log.warning(f"ERR {code}: {msg}")
    return make_response({"error": str(msg)}, code)

# ────────────────────────── request/response logs ──────────────────
@app.before_request
def _log_request_start():
    g._start = perf_counter()
    g._rid = request.headers.get("x-request-id") or uuid4().hex[:8]
    log.info(f"[{g._rid}] → {request.method} {request.path} qs={dict(request.args)}")
    if request.method in ("POST", "PUT", "PATCH"):
        try:
            body = request.get_json(silent=True)
            if body:
                redacted = dict(body)
                if "password" in redacted:
                    redacted["password"] = "***"
                log.info(f"[{g._rid}] body={json.dumps(redacted)[:800]}")
        except Exception:
            log.info(f"[{g._rid}] body=<non-json>")

@app.after_request
def _log_response(resp):
    dur_ms = (perf_counter() - g.get("_start", perf_counter())) * 1000
    log.info(f"[{g.get('_rid','-')}] ← {resp.status_code} {resp.content_type} {dur_ms:.1f}ms")
    return resp

@app.errorhandler(Exception)
def _unhandled(e):
    log.error(f"[{g.get('_rid','-')}] !!! {type(e).__name__}: {e}\n{traceback.format_exc()}")
    return err("internal server error", 500)

# ────────────────────────── auth helpers ───────────────────────────
def _bearer():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    return None

def auth_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = _bearer()
        if not token:
            return err("missing bearer token", 401)
        try:
            res = sb_public.auth.get_user(token)
            user = res.user
            if not user:
                return err("invalid token", 401)
            g.user_id = user.id
            g.user_email = user.email
            log.info(f"[{g._rid}] auth ok user_id={g.user_id}")
        except Exception as e:
            return err(f"invalid token: {e}", 401)
        return fn(*args, **kwargs)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not getattr(g, "user_id", None):
            return err("unauthorized", 401)
        try:
            rows = (
                sb_admin.table("user_profiles")
                .select("is_admin")
                .eq("user_id", g.user_id)
                .limit(1)
                .execute()
                .data
            )
            is_admin = bool(rows and rows[0].get("is_admin"))
            log.info(f"[{g._rid}] admin_required user_id={g.user_id} -> {is_admin}")
        except Exception as e:
            return err(f"profile lookup failed: {e}", 500)
        if not is_admin:
            return err("forbidden", 403)
        return fn(*args, **kwargs)
    return wrapper

# ────────────────────────── small utils ────────────────────────────
def ensure_bucket(name: str):
    try:
        buckets = sb_admin.storage.list_buckets()
        if not any(b.get("name") == name for b in buckets):
            app.logger.info(f"[storage] creating bucket {name}")
            sb_admin.storage.create_bucket(name, public=True)
    except Exception as e:
        app.logger.warning(f"[storage] ensure bucket failed: {e}")

def parse_data_url_png(data_url: str) -> bytes:
    # expects "data:image/png;base64,...."
    if not data_url or not data_url.startswith("data:image"):
        return b""
    header, b64 = data_url.split(",", 1)
    return base64.b64decode(b64)

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
            app.logger.warning(f"[pdf] embed signature failed: {e}")
    y -= 1.3 * inch

    c.showPage()
    c.save()
    buf.seek(0)
    return buf.read()

def to_utc_ts(sec: int) -> datetime:
    return datetime.fromtimestamp(sec, tz=timezone.utc)

def add_interval(dt: datetime, interval: str, count: int) -> datetime:
    """Add a plan interval to a datetime (supports day/week/month/year)."""
    interval = (interval or "").lower()
    count = int(count or 1)
    if interval == "day":
        return dt + timedelta(days=count)
    if interval == "week":
        return dt + timedelta(weeks=count)
    if interval == "month":
        # month roll-over safe (e.g., Jan 31 + 1 month -> Feb last day)
        month0 = dt.month - 1 + count
        year = dt.year + month0 // 12
        month = month0 % 12 + 1
        day = min(dt.day, calendar.monthrange(year, month)[1])
        return dt.replace(year=year, month=month, day=day)
    if interval == "year":
        try:
            return dt.replace(year=dt.year + count)
        except ValueError:
            # handle Feb 29 -> Feb 28
            return dt.replace(month=2, day=28, year=dt.year + count)
    # default fallback: 1 day
    return dt + timedelta(days=count)

def get_or_create_stripe_customer(user_id: str) -> str:
    prof = (
        sb_admin.table("user_profiles")
        .select("stripe_customer_id,email,first_name,last_name")
        .eq("user_id", user_id)
        .limit(1)
        .execute()
        .data
    )
    if not prof:
        raise ValueError("profile missing")

    prof = prof[0]
    cid = prof.get("stripe_customer_id")
    if cid:
        return cid

    full_name = " ".join([prof.get("first_name") or "", prof.get("last_name") or ""]).strip() or None
    customer = stripe.Customer.create(
        email=prof.get("email"),
        name=full_name,
        metadata={"user_id": user_id},
    )
    cid = customer.id
    sb_admin.table("user_profiles").update({"stripe_customer_id": cid}).eq("user_id", user_id).execute()
    log.info(f"[{g._rid}] created stripe customer {cid} for user {user_id}")
    return cid

def ensure_membership(
    owner_user_id: str,
    plan_id: str,
    *,
    subject_user_id: str | None = None,
    dependent_id: str | None = None,
    provider_customer_id: str | None = None,
    provider_subscription_id: str | None = None,
    status: str = "active",
):
    mem = None
    if provider_subscription_id:
        rows = (
            sb_admin.table("user_memberships")
            .select("*")
            .eq("provider_subscription_id", provider_subscription_id)
            .limit(1)
            .execute()
            .data
        )
        if rows:
            mem = rows[0]

    if not mem:
        q = (
            sb_admin.table("user_memberships")
            .select("*")
            .eq("owner_user_id", owner_user_id)
            .eq("plan_id", plan_id)
        )
        if subject_user_id:
            q = q.eq("subject_user_id", subject_user_id).is_("dependent_id", "null")
        else:
            q = q.eq("dependent_id", dependent_id).is_("subject_user_id", "null")
        rows = q.limit(1).execute().data
        if rows:
            mem = rows[0]

    if mem:
        patch = {}
        if provider_customer_id and not mem.get("provider_customer_id"):
            patch["provider_customer_id"] = provider_customer_id
        if provider_subscription_id and not mem.get("provider_subscription_id"):
            patch["provider_subscription_id"] = provider_subscription_id
        if status and mem.get("status") != status:
            patch["status"] = status
        if patch:
            mem = (
                sb_admin.table("user_memberships")
                .update(patch)
                .eq("id", mem["id"])
                .execute()
                .data[0]
            )
            log.info(f"[{g._rid}] updated membership {mem['id']} with {patch}")
        return mem

    payload = {
        "owner_user_id": owner_user_id,
        "plan_id": plan_id,
        "status": status,
        "provider_customer_id": provider_customer_id,
        "provider_subscription_id": provider_subscription_id,
    }
    if subject_user_id:
        payload["subject_user_id"] = subject_user_id
    else:
        payload["dependent_id"] = dependent_id

    mem = sb_admin.table("user_memberships").insert(payload).execute().data[0]
    log.info(f"[{g._rid}] created membership {mem['id']} payload={payload}")
    return mem

def has_signed_required_waiver(subject_type: str, subject_id: str) -> bool:
    """
    Returns True if:
      - there is no active waiver marked required_for_purchase, OR
      - the subject has a non-revoked signature for the current waiver version.
    """
    waivers = (
        sb_admin.table("waivers")
        .select("id,version,required_for_purchase")
        .eq("is_active", True)
        .eq("required_for_purchase", True)
        .limit(1)
        .execute()
        .data
    )
    if not waivers:
        log.info(f"[{g._rid}] has_signed_required_waiver: no required waiver → allow")
        return True

    w = waivers[0]
    q = (
        sb_admin.table("waiver_signatures")
        .select("id")
        .eq("waiver_id", w["id"])
        .eq("waiver_version", w["version"])
        .is_("revoked_at", "null")
    )
    if subject_type == "user":
        q = q.eq("subject_user_id", subject_id)
    else:
        q = q.eq("dependent_id", subject_id)

    signed = bool(q.limit(1).execute().data)
    log.info(f"[{g._rid}] has_signed_required_waiver subject_type={subject_type} subject_id={subject_id} -> {signed}")
    return signed

# ───────── helpers for access + check-ins + optional QR ────────────
def has_access_now_for_subject(subject_user_id: str | None, dependent_id: str | None) -> bool:
    now = datetime.now(timezone.utc)
    q = sb_admin.table("membership_periods").select("period_start,period_end").eq("is_voided", False)
    if subject_user_id:
        q = q.eq("subject_user_id", subject_user_id)
    else:
        q = q.eq("dependent_id", dependent_id)
    rows = q.execute().data
    for r in rows:
        try:
            ps = datetime.fromisoformat(r["period_start"])
            pe = datetime.fromisoformat(r["period_end"])
            if ps <= now < pe:
                return True
        except Exception:
            continue
    return False

def record_checkin(*, subject_type: str, subject_id: str, method: str = "qr",
                   location: str | None = None, source: str | None = None,
                   meta: dict | None = None) -> dict:
    row = {
        "subject_user_id": subject_id if subject_type == "user" else None,
        "dependent_id": subject_id if subject_type == "dependent" else None,
        "method": method or "qr",
        "location": location,
        "source": source,
        "meta": meta or {},
    }
    rec = sb_admin.table("gym_checkins").insert(row).execute().data[0]
    rec["has_access_now"] = has_access_now_for_subject(rec.get("subject_user_id"), rec.get("dependent_id"))
    return rec

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

def _b64url_decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + padding).encode("utf-8"))

def _sign_qr_body(body_b64: str, secret: str) -> str:
    mac = hmac.new(secret.encode("utf-8"), body_b64.encode("utf-8"), hashlib.sha256).digest()
    return _b64url(mac)

# ───────────────────────── health check ────────────────────────────
@app.get("/ping")
def ping():
    return {"status": "ok"}

# ───────────────────────── signup/login ────────────────────────────
@app.post("/signup")
def signup():
    body = request.get_json(force=True, silent=True) or {}
    email = body.get("email")
    password = body.get("password")
    if not email or not password:
        return err("email and password required", 400)

    try:
        res = sb_admin.auth.admin.create_user(
            {"email": email, "password": password, "email_confirm": True}
        )
        uid = res.user.id
        log.info(f"[{g._rid}] created auth user {uid}")
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
        log.info(f"[{g._rid}] upserted profile for {uid}")
    except Exception as e:
        try:
            sb_admin.auth.admin.delete_user(uid)
        except Exception:
            pass
        return err(f"profile insert failed: {e}", 500)

    return {"user_id": uid}, 201

@app.post("/login")
def login():
    body = request.get_json(force=True, silent=True) or {}
    email = body.get("email")
    password = body.get("password")
    if not email or not password:
        return err("email and password required", 400)

    try:
        res = sb_public.auth.sign_in_with_password({"email": email, "password": password})
        session = res.session
        log.info(f"[{g._rid}] login ok user_id={res.user.id}")
        return {
            "access_token": session.access_token,
            "refresh_token": session.refresh_token,
            "user_id": res.user.id,
            "expires_in": session.expires_in,
            "token_type": session.token_type,
        }, 200
    except Exception as e:
        return err(f"invalid login: {e}", 401)

# ───────────────────────── profiles / plans ────────────────────────
@app.get("/api/profile/me")
@auth_required
def profile_me():
    rows = (
        sb_admin.table("user_profiles")
        .select("*")
        .eq("user_id", g.user_id)
        .limit(1)
        .execute()
        .data
    )
    if not rows:
        return err("profile not found", 404)
    log.info(f"[{g._rid}] profile_me user_id={g.user_id}")
    return jsonify(rows[0])

@app.get("/api/plans")
def list_plans():
    """Public: list active plans (now includes slug & checkout mode)."""
    try:
        rows = (
            sb_admin.table("membership_plans")
            .select("id,slug,name,description,price_cents,currency,interval,interval_count,stripe_price_id,stripe_checkout_mode")
            .eq("is_active", True)
            .order("price_cents", desc=False)
            .execute()
            .data
        )
        log.info(f"[{g._rid}] list_plans count={len(rows)}")
        return jsonify(rows)
    except Exception as e:
        return err(f"failed to load plans: {e}", 500)

# ───────────────────────── waiver endpoints ────────────────────────
@app.get("/api/waivers/active")
@auth_required
def waiver_active():
    """
    Return the *required-for-purchase* active waiver (if any) and whether the subject has signed it.
    """
    subject_type = (request.args.get("subjectType") or "user").lower()
    subject_id = request.args.get("subjectId")
    if subject_type not in ("user", "dependent"):
        return err("subjectType must be 'user' or 'dependent'", 400)
    if subject_type == "user":
        subject_id = g.user_id
    elif not subject_id:
        return err("subjectId required for dependent", 400)

    waivers = (
        sb_admin.table("waivers")
        .select("*")
        .eq("is_active", True)
        .eq("required_for_purchase", True)
        .limit(1)
        .execute()
        .data
    )
    if not waivers:
        log.info(f"[{g._rid}] waiver_active none")
        return jsonify({"waiver": None, "signed": False})

    w = waivers[0]
    q = sb_admin.table("waiver_signatures").select("id").eq("waiver_id", w["id"]).eq("waiver_version", w["version"])
    if subject_type == "user":
        q = q.eq("subject_user_id", subject_id).is_("revoked_at", "null")
    else:
        q = q.eq("dependent_id", subject_id).is_("revoked_at", "null")
    signed = bool(q.limit(1).execute().data)

    log.info(f"[{g._rid}] waiver_active found version={w['version']} signed={signed} subject_type={subject_type}")
    return jsonify({"waiver": w, "signed": signed})

@app.post("/api/waivers/sign")
@auth_required
def waiver_sign():
    body = request.get_json(force=True, silent=True) or {}
    subject_type = (body.get("subject_type") or "user").lower()
    subject_id = body.get("subject_id")
    if subject_type not in ("user", "dependent"):
        return err("subject_type must be 'user' or 'dependent'", 400)
    if subject_type == "user":
        subject_id = g.user_id
    elif not subject_id:
        return err("subject_id required for dependent", 400)

    # active required waiver
    waivers = (
        sb_admin.table("waivers")
        .select("*")
        .eq("is_active", True)
        .eq("required_for_purchase", True)
        .limit(1)
        .execute()
        .data
    )
    if not waivers:
        return err("no active waiver to sign", 400)
    w = waivers[0]

    # Optional: handle signature image (PNG data URL if provided)
    sig_png_bytes = b""
    sig_data_url = body.get("signature_data_url")
    if sig_data_url:
        try:
            sig_png_bytes = parse_data_url_png(sig_data_url)
        except Exception as e:
            app.logger.warning(f"[waiver] parse signature_data_url failed: {e}")

    payload = {
        "waiver_id": w["id"],
        "waiver_version": w["version"],
        "signed_by_user_id": g.user_id,
        "relationship_to_subject": body.get("relationship_to_subject"),
        "full_name": body.get("full_name"),
        "date_of_birth": body.get("date_of_birth"),
        "signature_svg": body.get("signature_svg"),  # optional legacy field
        "signature_image_url": None,                 # upload below
        "pdf_url": None,                             # upload below
        "ip_address": request.remote_addr,
        "user_agent": request.headers.get("User-Agent"),
    }
    if subject_type == "user":
        payload["subject_user_id"] = subject_id
    else:
        payload["dependent_id"] = subject_id

    # Insert first to get signature id
    try:
        sig = sb_admin.table("waiver_signatures").insert(payload).execute().data[0]
        sig_id = sig["id"]
    except Exception as e:
        return err(f"sign insert failed: {e}", 400)

    # Build + upload assets
    ensure_bucket(WAIVER_BUCKET)
    signed_at = datetime.now(timezone.utc)
    try:
        # Signature image
        sig_url = None
        if sig_png_bytes:
            sig_path = f"signatures/{sig_id}.png"
            app.logger.info(f"[storage] upload signature {sig_path} ({len(sig_png_bytes)} bytes)")
            sb_admin.storage.from_(WAIVER_BUCKET).upload(
                sig_path, sig_png_bytes, {"content-type": "image/png", "upsert": True}
            )
            sig_url = sb_admin.storage.from_(WAIVER_BUCKET).get_public_url(sig_path).get("publicURL")

        # PDF
        pdf_bytes = build_waiver_pdf(
            waiver=w,
            full_name=payload["full_name"] or "",
            dob_str=payload["date_of_birth"] or "",
            signed_at_dt=signed_at,
            ip=payload["ip_address"],
            ua=payload["user_agent"],
            sig_png_bytes=sig_png_bytes,
        )
        pdf_path = f"pdf/{sig_id}.pdf"
        app.logger.info(f"[storage] upload pdf {pdf_path} ({len(pdf_bytes)} bytes)")
        sb_admin.storage.from_(WAIVER_BUCKET).upload(
            pdf_path, pdf_bytes, {"content-type": "application/pdf", "upsert": True}
        )
        pdf_url = sb_admin.storage.from_(WAIVER_BUCKET).get_public_url(pdf_path).get("publicURL")

        # Update row with urls
        sig = (
            sb_admin.table("waiver_signatures")
            .update({"signature_image_url": sig_url, "pdf_url": pdf_url})
            .eq("id", sig_id)
            .execute()
            .data[0]
        )
    except Exception as e:
        app.logger.warning(f"[waiver] asset upload failed: {e}")

    # Optional: reflect on profile (legacy field)
    if subject_type == "user":
        try:
            sb_admin.table("user_profiles").update({"signed_waiver": True}).eq("user_id", subject_id).execute()
        except Exception:
            pass

    return jsonify(sig), 201

# ───────────────────────── checkout/session ────────────────────────
@app.post("/api/checkout/session")
@auth_required
def create_checkout_session():
    if not STRIPE_SECRET_KEY:
        return err("stripe not configured", 500)

    body = request.get_json(force=True, silent=True) or {}
    plan_id = body.get("plan_id")
    plan_slug = body.get("plan_slug")
    subject_type = (body.get("subject_type") or "user").lower()
    subject_id = body.get("subject_id")

    if subject_type not in ("user", "dependent"):
        return err("subject_type must be 'user' or 'dependent'", 400)
    if subject_type == "user":
        subject_id = g.user_id
    elif not subject_id:
        return err("subject_id required for dependent", 400)

    # Enforce waiver before starting Stripe checkout
    if not has_signed_required_waiver(subject_type, subject_id):
        return err("You must sign the current waiver before purchasing.", 400)

    # Load plan by id or slug (active only)
    if plan_id:
        sel = sb_admin.table("membership_plans").select("*").eq("id", plan_id).eq("is_active", True).limit(1)
    elif plan_slug:
        sel = sb_admin.table("membership_plans").select("*").eq("slug", plan_slug).eq("is_active", True).limit(1)
    else:
        return err("plan_id or plan_slug required", 400)

    plans = sel.execute().data
    if not plans:
        return err("plan not found or inactive", 404)
    plan = plans[0]
    price_id = plan.get("stripe_price_id")
    if not price_id:
        return err("plan missing stripe_price_id", 400)

    checkout_mode = (plan.get("stripe_checkout_mode") or "subscription").lower()
    if checkout_mode not in ("subscription", "payment"):
        return err("invalid plan checkout mode", 400)

    customer_id = get_or_create_stripe_customer(g.user_id)

    md = {
        "owner_user_id": g.user_id,
        "plan_id": plan["id"],
        "subject_user_id": g.user_id if subject_type == "user" else "",
        "dependent_id": subject_id if subject_type == "dependent" else "",
    }
    log.info(
        f"[{g._rid}] checkout start owner={g.user_id} plan={plan['id']} price={price_id} "
        f"mode={checkout_mode} customer={customer_id} subject_type={subject_type} subject_id={subject_id}"
    )

    try:
        if checkout_mode == "subscription":
            sess = stripe.checkout.Session.create(
                mode="subscription",
                line_items=[{"price": price_id, "quantity": 1}],
                customer=customer_id,
                success_url=f"{FRONTEND_URL}/billing/success?session_id={{CHECKOUT_SESSION_ID}}",
                cancel_url=f"{FRONTEND_URL}/billing/cancel",
                metadata=md,
                subscription_data={"metadata": md},
            )
        else:
            # One-time payment (e.g., day pass)
            sess = stripe.checkout.Session.create(
                mode="payment",
                line_items=[{"price": price_id, "quantity": 1}],
                customer=customer_id,
                success_url=f"{FRONTEND_URL}/billing/success?session_id={{CHECKOUT_SESSION_ID}}",
                cancel_url=f"{FRONTEND_URL}/billing/cancel",
                metadata=md,
            )
        log.info(f"[{g._rid}] checkout session created id={sess.id}")
    except Exception as e:
        return err(f"stripe checkout error: {e}", 400)

    return jsonify({"checkout_url": sess.url})

# ───────────────────────── stripe webhook ──────────────────────────
@app.post("/webhooks/stripe")
def stripe_webhook():
    if not STRIPE_WEBHOOK_SECRET:
        return err("webhook not configured", 500)

    payload = request.data
    sig = request.headers.get("Stripe-Signature", "")
    try:
        event = stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)
    except Exception as e:
        return err(f"webhook signature failed: {e}", 400)

    etype = event["type"]
    log.info(f"[{uuid4().hex[:8]}] stripe event {etype}")

    # Helper: create a membership_period for a one-time plan (mode=payment)
    def _ensure_one_time_period(meta: dict, amount_total: int | None, currency: str | None, external_id: str | None, created_ts: int | None):
        plan_id = meta.get("plan_id")
        owner_user_id = meta.get("owner_user_id")
        subject_user_id = meta.get("subject_user_id") or None
        dependent_id = meta.get("dependent_id") or None

        if not (plan_id and owner_user_id):
            return

        # Load plan to compute coverage window
        plan_rows = (
            sb_admin.table("membership_plans")
            .select("id,interval,interval_count")
            .eq("id", plan_id)
            .limit(1)
            .execute()
            .data
        )
        if not plan_rows:
            return
        plan = plan_rows[0]

        # Ensure a membership "relationship" row exists
        mem = ensure_membership(
            owner_user_id=owner_user_id,
            plan_id=plan_id,
            subject_user_id=subject_user_id or owner_user_id if (subject_user_id and not dependent_id) else subject_user_id,
            dependent_id=dependent_id,
            status="active",
        )

        # Idempotency: don't duplicate periods/receipts for same external id
        if external_id:
            existing = (
                sb_admin.table("membership_periods")
                .select("id")
                .eq("source", "stripe")
                .eq("source_ref", external_id)
                .limit(1)
                .execute()
                .data
            )
            if existing:
                return

        start = to_utc_ts(created_ts) if created_ts else datetime.now(timezone.utc)
        end = add_interval(start, plan.get("interval") or "day", plan.get("interval_count") or 1)

        sb_admin.table("membership_periods").insert({
            "user_membership_id": mem["id"],
            "owner_user_id": mem["owner_user_id"],
            "subject_user_id": mem.get("subject_user_id"),
            "dependent_id": mem.get("dependent_id"),
            "plan_id": mem["plan_id"],
            "source": "stripe",
            "source_ref": external_id,
            "period_start": start,
            "period_end": end,
        }).execute()

        # Optional receipt for one-time
        if external_id and amount_total is not None:
            rec_existing = (
                sb_admin.table("payment_receipts")
                .select("id")
                .eq("source", "stripe")
                .eq("external_id", external_id)
                .limit(1)
                .execute()
                .data
            )
            if not rec_existing:
                sb_admin.table("payment_receipts").insert({
                    "user_membership_id": mem["id"],
                    "owner_user_id": mem["owner_user_id"],
                    "subject_user_id": mem.get("subject_user_id"),
                    "dependent_id": mem.get("dependent_id"),
                    "plan_id": mem["plan_id"],
                    "source": "stripe",
                    "external_type": "checkout_session",
                    "external_id": external_id,
                    "status": "succeeded",
                    "amount_cents": int(amount_total or 0),
                    "currency": (currency or "USD").upper(),
                    "paid_at": datetime.now(timezone.utc),
                }).execute()

        # Keep membership active
        sb_admin.table("user_memberships").update({"status": "active"}).eq("id", mem["id"]).execute()

    if etype == "checkout.session.completed":
        sess = event["data"]["object"]
        mode = sess.get("mode")
        customer_id = sess.get("customer")
        md = sess.get("metadata", {}) or {}
        plan_id = md.get("plan_id")
        owner_user_id = md.get("owner_user_id")
        subject_user_id = md.get("subject_user_id") or None
        dependent_id = md.get("dependent_id") or None

        log.info(f"checkout.completed mode={mode} cust={customer_id} owner={owner_user_id} plan={plan_id} subj={subject_user_id} dep={dependent_id}")

        if mode == "subscription":
            sub_id = sess.get("subscription")
            if not (plan_id and owner_user_id and sub_id and customer_id):
                return jsonify({"ok": True})
            ensure_membership(
                owner_user_id=owner_user_id,
                plan_id=plan_id,
                subject_user_id=subject_user_id,
                dependent_id=dependent_id,
                provider_customer_id=customer_id,
                provider_subscription_id=sub_id,
                status="active",
            )
            return jsonify({"ok": True})

        # One-time payment: grant access period right away
        if mode == "payment":
            amount_total = sess.get("amount_total")
            currency = sess.get("currency")
            created_ts = sess.get("created")
            external_id = sess.get("id")  # session id as receipt/period source
            _ensure_one_time_period(md, amount_total, currency, external_id, created_ts)
            return jsonify({"ok": True})

        return jsonify({"ok": True})

    if etype == "invoice.paid":
        inv = event["data"]["object"]
        sub_id = inv.get("subscription")
        invoice_id = inv.get("id")
        amount_paid = inv.get("amount_paid") or 0
        currency = (inv.get("currency") or "usd").upper()
        log.info(f"invoice.paid sub={sub_id} invoice={invoice_id} amount={amount_paid} {currency}")

        mem_rows = (
            sb_admin.table("user_memberships")
            .select("*")
            .eq("provider_subscription_id", sub_id)
            .limit(1)
            .execute()
            .data
        )
        if not mem_rows:
            log.warning(f"invoice.paid: no membership for sub={sub_id}")
            return jsonify({"ok": True})
        mem = mem_rows[0]

        lines = inv.get("lines", {}).get("data", [])
        if not lines:
            return jsonify({"ok": True})
        period = lines[0].get("period", {})
        start_ts = period.get("start")
        end_ts = period.get("end")
        if not (start_ts and end_ts):
            return jsonify({"ok": True})

        existing = (
            sb_admin.table("membership_periods")
            .select("id")
            .eq("source", "stripe")
            .eq("source_ref", invoice_id)
            .limit(1)
            .execute()
            .data
        )
        if not existing:
            mp_payload = {
                "user_membership_id": mem["id"],
                "owner_user_id": mem["owner_user_id"],
                "subject_user_id": mem.get("subject_user_id"),
                "dependent_id": mem.get("dependent_id"),
                "plan_id": mem["plan_id"],
                "source": "stripe",
                "source_ref": invoice_id,
                "period_start": to_utc_ts(start_ts),
                "period_end": to_utc_ts(end_ts),
            }
            sb_admin.table("membership_periods").insert(mp_payload).execute()
            log.info(f"period added for invoice={invoice_id} mem={mem['id']}")

        rec_existing = (
            sb_admin.table("payment_receipts")
            .select("id")
            .eq("source", "stripe")
            .eq("external_id", invoice_id)
            .limit(1)
            .execute()
            .data
        )
        if not rec_existing:
            receipt = {
                "user_membership_id": mem["id"],
                "owner_user_id": mem["owner_user_id"],
                "subject_user_id": mem.get("subject_user_id"),
                "dependent_id": mem.get("dependent_id"),
                "plan_id": mem["plan_id"],
                "source": "stripe",
                "external_type": "invoice",
                "external_id": invoice_id,
                "status": "succeeded",
                "amount_cents": int(amount_paid or 0),
                "currency": currency,
                "paid_at": datetime.now(timezone.utc),
            }
            sb_admin.table("payment_receipts").insert(receipt).execute()
            log.info(f"receipt recorded for invoice={invoice_id}")

        sb_admin.table("user_memberships").update({"status": "active"}).eq("id", mem["id"]).execute()
        return jsonify({"ok": True})

    if etype in ("invoice.payment_failed",):
        inv = event["data"]["object"]
        sub_id = inv.get("subscription")
        log.warning(f"invoice.payment_failed sub={sub_id}")
        sb_admin.table("user_memberships").update({"status": "past_due"}).eq("provider_subscription_id", sub_id).execute()
        return jsonify({"ok": True})

    if etype in ("customer.subscription.deleted",):
        sub = event["data"]["object"]
        sub_id = sub.get("id")
        ends_at = sub.get("current_period_end")
        patch = {"status": "canceled"}
        if ends_at:
            patch["current_period_end"] = to_utc_ts(ends_at)
        log.info(f"subscription.deleted sub={sub_id} ends_at={ends_at}")
        sb_admin.table("user_memberships").update(patch).eq("provider_subscription_id", sub_id).execute()
        return jsonify({"ok": True})

    return jsonify({"ok": True})

# ───────────────────────── access check ────────────────────────────
@app.get("/api/access/status")
@auth_required
def access_status():
    subject_type = (request.args.get("subjectType") or "user").lower()
    subject_id = request.args.get("subjectId")
    if subject_type not in ("user", "dependent"):
        return err("subjectType must be 'user' or 'dependent'", 400)
    if subject_type == "user":
        subject_id = g.user_id
    elif not subject_id:
        return err("subjectId required for dependent", 400)

    q = sb_admin.table("membership_periods").select("period_start,period_end").eq("is_voided", False)
    if subject_type == "user":
        q = q.eq("subject_user_id", subject_id)
    else:
        q = q.eq("dependent_id", subject_id)
    now = datetime.now(timezone.utc)

    rows = q.execute().data
    can_enter = any(
        (datetime.fromisoformat(r["period_start"]) <= now < datetime.fromisoformat(r["period_end"]))
        for r in rows
    )
    log.info(f"[{g._rid}] access_status subject_type={subject_type} can_enter={can_enter}")
    return jsonify({"subject_type": subject_type, "subject_id": subject_id, "can_enter": can_enter})

# ───────────────────────── admin manual/cash periods ───────────────
@app.post("/api/admin/periods")
@auth_required
@admin_required
def admin_add_period():
    body = request.get_json(force=True, silent=True) or {}

    user_membership_id = body.get("user_membership_id")
    owner_user_id = body.get("owner_user_id") or g.user_id
    subject_type = (body.get("subject_type") or "user").lower()
    subject_id = body.get("subject_id")
    plan_id = body.get("plan_id")
    period_start = body.get("period_start")
    period_end = body.get("period_end")
    amount_cents = body.get("amount_cents") or 0
    notes = body.get("notes")

    if not (period_start and period_end and plan_id):
        return err("period_start, period_end, plan_id required", 400)
    if subject_type not in ("user", "dependent"):
        return err("subject_type must be 'user' or 'dependent'", 400)
    if subject_type == "dependent" and not subject_id:
        return err("subject_id required for dependent", 400)

    mem = None
    if user_membership_id:
        rows = sb_admin.table("user_memberships").select("*").eq("id", user_membership_id).limit(1).execute().data
        if rows:
            mem = rows[0]
    if not mem:
        mem = ensure_membership(
            owner_user_id=owner_user_id,
            plan_id=plan_id,
            subject_user_id=(owner_user_id if subject_type == "user" else None),
            dependent_id=(subject_id if subject_type == "dependent" else None),
            status="active",
        )

    mp = {
        "user_membership_id": mem["id"],
        "owner_user_id": mem["owner_user_id"],
        "subject_user_id": mem.get("subject_user_id"),
        "dependent_id": mem.get("dependent_id"),
        "plan_id": mem["plan_id"],
        "source": "manual",
        "source_ref": None,
        "period_start": period_start,
        "period_end": period_end,
    }
    sb_admin.table("membership_periods").insert(mp).execute()
    log.info(f"[{g._rid}] admin added period mem={mem['id']} {period_start}..{period_end}")

    if amount_cents:
        receipt = {
            "user_membership_id": mem["id"],
            "owner_user_id": mem["owner_user_id"],
            "subject_user_id": mem.get("subject_user_id"),
            "dependent_id": mem.get("dependent_id"),
            "plan_id": mem["plan_id"],
            "source": "manual",
            "external_type": None,
            "external_id": None,
            "status": "succeeded",
            "amount_cents": int(amount_cents),
            "currency": "USD",
            "notes": notes,
            "paid_at": datetime.now(timezone.utc),
            "created_by_user_id": g.user_id,
        }
        sb_admin.table("payment_receipts").insert(receipt).execute()
        log.info(f"[{g._rid}] admin recorded cash receipt mem={mem['id']} amt={amount_cents}")

    sb_admin.table("user_memberships").update({"status": "active"}).eq("id", mem["id"]).execute()
    return jsonify({"ok": True})

# ───────────────────────── admin: manual check-in ──────────────────
@app.post("/api/admin/checkins")
@auth_required
@admin_required
def admin_checkin():
    body = request.get_json(force=True, silent=True) or {}
    subject_type = (body.get("subject_type") or "user").lower()
    subject_id = body.get("subject_id")
    if subject_type not in ("user", "dependent") or not subject_id:
        return err("subject_type ('user'|'dependent') and subject_id required", 400)

    rec = record_checkin(
        subject_type=subject_type,
        subject_id=subject_id,
        method=body.get("method") or "admin",
        location=body.get("location"),
        source=body.get("source") or f"admin:{g.user_id}",
        meta=body.get("meta") or {},
    )
    return jsonify({"ok": True, "checkin": rec})

# ───────────────────────── QR token endpoints (optional) ───────────
@app.get("/api/checkins/qr-token")
@auth_required
def issue_qr_token():
    if not CHECKIN_QR_SECRET:
        return err("QR secret not configured", 500)

    ttl = int(request.args.get("ttl", "300"))  # default 5 minutes
    ttl = max(60, min(ttl, 3600))              # clamp 1–60 minutes
    payload = {"uid": g.user_id, "exp": int(time.time()) + ttl}

    body_b64 = _b64url(json.dumps(payload).encode("utf-8"))
    sig_b64 = _sign_qr_body(body_b64, CHECKIN_QR_SECRET)
    token = f"{body_b64}.{sig_b64}"
    return jsonify({"token": token, "expires_at": payload["exp"]})

@app.post("/api/checkins/scan")
def scan_qr_and_checkin():
    if not CHECKIN_QR_SECRET:
        return err("QR secret not configured", 500)

    body = request.get_json(force=True, silent=True) or {}
    token = body.get("token") or ""
    location = body.get("location") or "front_desk"
    source = body.get("source") or f"kiosk:{request.remote_addr}"

    try:
        body_b64, sig_b64 = token.split(".", 1)
        expected = _sign_qr_body(body_b64, CHECKIN_QR_SECRET)
        if not hmac.compare_digest(expected, sig_b64):
            return err("invalid token signature", 401)

        payload = json.loads(_b64url_decode(body_b64))
        if int(payload["exp"]) < int(time.time()):
            return err("token expired", 401)

        user_id = payload["uid"]
    except Exception as e:
        return err(f"invalid token: {e}", 401)

    rec = record_checkin(
        subject_type="user",
        subject_id=user_id,
        method="qr",
        location=location,
        source=source,
        meta={"remote_addr": request.remote_addr, "ua": request.headers.get("User-Agent")},
    )

    prof_rows = (
        sb_admin.table("user_profiles")
        .select("first_name,last_name,email")
        .eq("user_id", user_id)
        .limit(1)
        .execute()
        .data
    )
    prof = prof_rows[0] if prof_rows else {}
    return jsonify({
        "ok": True,
        "checkin": rec,
        "user": {
            "first_name": prof.get("first_name"),
            "last_name": prof.get("last_name"),
            "email": prof.get("email"),
        },
    })

# ───────────────────────── dev: seed and stripe ping ───────────────
def _dev_allowed() -> bool:
    return request.remote_addr in ("127.0.0.1", "::1") or ENABLE_DEV_ROUTES

@app.post("/dev/seed")
def dev_seed():
    if not _dev_allowed():
        return err("dev routes disabled", 403)

    created = {"plans": None, "waiver": None}

    # Seed plan if table empty OR specific price id missing
    plans = sb_admin.table("membership_plans").select("id, stripe_price_id").execute().data
    if not plans:
        payload = {
            "name": "Monthly Membership",
            "description": "Standard monthly access",
            "price_cents": 3999,
            "currency": "USD",
            "interval": "month",
            "interval_count": 1,
            "is_active": True,
            "stripe_price_id": STRIPE_PRICE_ID_MONTHLY,
        }
        created["plans"] = sb_admin.table("membership_plans").insert(payload).execute().data
        log.info(f"seeded membership_plans (new table) {created['plans']}")
    else:
        if STRIPE_PRICE_ID_MONTHLY and not any((p.get("stripe_price_id") == STRIPE_PRICE_ID_MONTHLY) for p in plans):
            payload = {
                "name": "Monthly Membership",
                "description": "Standard monthly access",
                "price_cents": 3999,
                "currency": "USD",
                "interval": "month",
                "interval_count": 1,
                "is_active": True,
                "stripe_price_id": STRIPE_PRICE_ID_MONTHLY,
            }
            created["plans"] = sb_admin.table("membership_plans").insert(payload).execute().data
            log.info("seeded membership_plans (added price-based plan)")

    # Seed active waiver if none
    active = (
        sb_admin.table("waivers")
        .select("id")
        .eq("is_active", True)
        .eq("required_for_purchase", True)
        .limit(1)
        .execute()
        .data
    )
    if not active:
        slug = "general-liability"
        version = 1
        title = "General Liability Waiver"
        body = (
            "By signing this waiver, I acknowledge the inherent risks of physical exercise and agree to "
            "release the gym and its employees from any liability arising from my participation."
        )
        hashed = hashlib.sha256(f"{slug}:{version}:{title}:{body}".encode("utf-8")).hexdigest()
        waiver = {
            "slug": slug,
            "version": version,
            "title": title,
            "body": body,
            "hash": hashed,
            "is_active": True,
            "required_for_purchase": True,
        }
        created["waiver"] = sb_admin.table("waivers").insert(waiver).execute().data
        log.info("seeded active waiver")

    return jsonify({"ok": True, "created": created})

@app.get("/debug/stripe/ping")
def stripe_ping():
    if not _dev_allowed():
        return err("dev routes disabled", 403)
    if not STRIPE_SECRET_KEY:
        return err("STRIPE_SECRET_KEY not set", 500)

    try:
        me = stripe.Account.retrieve()
        out = {"account": {"id": me.id, "country": me.country}}
        if STRIPE_PRICE_ID_MONTHLY:
            price = stripe.Price.retrieve(STRIPE_PRICE_ID_MONTHLY)
            out["price"] = {
                "id": price.id,
                "unit_amount": price.unit_amount,
                "currency": price.currency,
                "recurring": price.get("recurring"),
            }
        return jsonify(out)
    except Exception as e:
        return err(f"stripe ping failed: {e}", 500)

# ───────────────────────── admin: users overview ───────────────────
@app.get("/api/admin/users/overview")
@auth_required
@admin_required
def admin_users_overview():
    """
    Returns:
      {
        "users": [{
          "user_id": "...",
          "email": "...",
          "first_name": "...",
          "last_name": "...",
          "last_checkin_at": ISO8601 | null,
          "has_access_now": bool,
          "memberships": [{ "id": "...", "status": "...", "plan": {...} | null }]
        }],
        "count": <int>
      }
    """
    rid = getattr(g, "_rid", "-")
    now = datetime.now(timezone.utc)

    try:
        # 1) Users
        users: List[dict] = (
            sb_admin.table("user_profiles")
            .select("user_id,email,first_name,last_name")
            .order("first_name", desc=False)
            .execute()
            .data
        )
        subject_ids = [u["user_id"] for u in users if u.get("user_id")]
        log.info(f"[{rid}] admin/overview users={len(users)}")

        # 2) Memberships
        memberships: List[dict] = []
        if subject_ids:
            memberships = (
                sb_admin.table("user_memberships")
                .select("id,owner_user_id,subject_user_id,plan_id,status")
                .in_("subject_user_id", subject_ids)
                .execute()
                .data
            )
        log.info(f"[{rid}] admin/overview memberships={len(memberships)}")

        # 3) Plans
        plan_ids = {m["plan_id"] for m in memberships if m.get("plan_id")}
        plans_by_id: Dict[str, dict] = {}
        if plan_ids:
            plans = (
                sb_admin.table("membership_plans")
                .select("id,name,price_cents,currency,interval,interval_count")
                .in_("id", list(plan_ids))
                .execute()
                .data
            )
            plans_by_id = {p["id"]: p for p in plans}
        log.info(f"[{rid}] admin/overview distinct_plans={len(plan_ids)} fetched={len(plans_by_id)}")

        # 4) Coverage windows for access
        periods_by_subject: Dict[str, List[dict]] = {}
        if subject_ids:
            per_user = (
                sb_admin.table("membership_periods")
                .select("subject_user_id,period_start,period_end,is_voided")
                .in_("subject_user_id", subject_ids)
                .eq("is_voided", False)
                .execute()
                .data
            )
            for r in per_user:
                sid = r["subject_user_id"]
                periods_by_subject.setdefault(sid, []).append(r)

        def active_now(periods: List[dict]) -> bool:
            for pr in periods or []:
                try:
                    ps = datetime.fromisoformat(pr["period_start"])
                    pe = datetime.fromisoformat(pr["period_end"])
                    if ps <= now < pe:
                        return True
                except Exception:
                    continue
            return False

        # 5) Latest check-in per subject (from gym_checkins)
        last_checkin_by_subject: Dict[str, str] = {}
        if subject_ids:
            ch = (
                sb_admin.table("gym_checkins")
                .select("subject_user_id,scanned_at")
                .in_("subject_user_id", subject_ids)
                .order("scanned_at", desc=True)
                .execute()
                .data
            )
            for row in ch:
                sid = row["subject_user_id"]
                if sid and sid not in last_checkin_by_subject:
                    last_checkin_by_subject[sid] = row["scanned_at"]

        # 6) Shape response
        mems_by_subject: Dict[str, List[dict]] = {}
        for m in memberships:
            sid = m["subject_user_id"]
            mems_by_subject.setdefault(sid, []).append(m)

        out_rows = []
        for u in users:
            sid = u["user_id"]
            u_mems = mems_by_subject.get(sid, [])
            mems_fmt = []
            for m in u_mems:
                plan = plans_by_id.get(m.get("plan_id"))
                mems_fmt.append({"id": m["id"], "status": m.get("status"), "plan": plan or None})
            out_rows.append({
                "user_id": sid,
                "email": u.get("email"),
                "first_name": u.get("first_name"),
                "last_name": u.get("last_name"),
                "last_checkin_at": last_checkin_by_subject.get(sid),
                "has_access_now": active_now(periods_by_subject.get(sid, [])),
                "memberships": mems_fmt,
            })

        return jsonify({"users": out_rows, "count": len(out_rows)})

    except Exception as e:
        log.error(f"[{rid}] admin/overview failed: {e}")
        return err(f"admin overview failed: {e}", 500)
    # ───────────────────────── user: my check‑ins ──────────────────────
@app.get("/api/checkins/mine")
@auth_required
def my_checkins():
    """
    Returns the current user's recent check-ins:
    {
      "items": [{
         "id": "...",
         "subject_user_id": "...",
         "dependent_id": null,
         "method": "qr|admin|...",
         "location": "front_desk",
         "source": "kiosk:127.0.0.1",
         "scanned_at": "2025-08-25T14:12:01.123456+00:00",
         "meta": {...}
      }],
      "count": <int>
    }
    """
    try:
        # Allow caller to tune size (sane limits)
        limit = min(max(int(request.args.get("limit", "100")), 1), 200)

        rows = (
            sb_admin.table("gym_checkins")
            .select("id,subject_user_id,dependent_id,method,location,source,scanned_at,meta")
            .eq("subject_user_id", g.user_id)
            .order("scanned_at", desc=True)
            .limit(limit)
            .execute()
            .data
        )
        return jsonify({"items": rows, "count": len(rows)})
    except Exception as e:
        return err(f"failed to load check-ins: {e}", 500)


# ───────────────────────── run dev server ──────────────────────────
if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    log.info(f"Starting server on 0.0.0.0:{port}  FRONTEND_URL={FRONTEND_URL}")
    app.run(host="0.0.0.0", port=port, debug=True)
