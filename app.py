# app.py — waiver‑gated checkout + subscriptions + one‑time + admin link/backfill
import re
import os
import json
import logging
import traceback
import calendar
import hmac
import hashlib
from uuid import uuid4
from time import perf_counter
from datetime import datetime, timezone, timedelta
from typing import Dict, List
import time
import threading

from flask import Flask, jsonify, request, make_response, g
from dotenv import load_dotenv
from flask_cors import CORS
from functools import wraps
from werkzeug.exceptions import HTTPException
from routes.admin import admin_bp
import stripe

from supabase import create_client, Client
from supabase.lib.client_options import SyncClientOptions as ClientOptions

import io
import textwrap
import base64
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.utils import ImageReader
import requests
import html as html_lib

# ────────────────────────── env / clients ──────────────────────────
load_dotenv()
# ───────── In-memory throttle for Stripe sync (NO DB CHANGES) ─────────
_STRIPE_SYNC_LAST: dict[str, float] = {}
_STRIPE_SYNC_LOCKS: dict[str, threading.Lock] = {}
_STRIPE_SYNC_LOCKS_GUARD = threading.Lock()

def _get_user_lock(user_id: str) -> threading.Lock:
    with _STRIPE_SYNC_LOCKS_GUARD:
        lock = _STRIPE_SYNC_LOCKS.get(user_id)
        if not lock:
            lock = threading.Lock()
            _STRIPE_SYNC_LOCKS[user_id] = lock
        return lock

SUPABASE_URL = os.environ["SUPABASE_URL"]
SERVICE_KEY = os.environ["SUPABASE_SERVICE_ROLE"]
ANON_KEY = os.getenv("SUPABASE_ANON")

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173").rstrip("/")
WAIVER_BUCKET = os.getenv("WAIVER_BUCKET", "waivers")
# ────────────────────────── mailchimp config ──────────────────────────
MAILCHIMP_API_KEY = (os.getenv("MAILCHIMP_API_KEY") or "").strip()
MAILCHIMP_AUDIENCE_ID = (os.getenv("MAILCHIMP_AUDIENCE_ID") or "").strip()
MAILCHIMP_SERVER_PREFIX = (os.getenv("MAILCHIMP_SERVER_PREFIX") or "").strip()
MAILCHIMP_FROM_NAME = (os.getenv("MAILCHIMP_FROM_NAME") or "Showtime Boxing").strip()
MAILCHIMP_REPLY_TO = (os.getenv("MAILCHIMP_REPLY_TO") or "info@showtimeboxinggym.com").strip()

# Many Mailchimp API keys are like "...-us21"
if MAILCHIMP_API_KEY and not MAILCHIMP_SERVER_PREFIX and "-" in MAILCHIMP_API_KEY:
    MAILCHIMP_SERVER_PREFIX = MAILCHIMP_API_KEY.split("-")[-1].strip()

MAILCHIMP_BASE_URL = f"https://{MAILCHIMP_SERVER_PREFIX}.api.mailchimp.com/3.0" if MAILCHIMP_SERVER_PREFIX else ""

def _mailchimp_enabled() -> bool:
    return bool(MAILCHIMP_API_KEY and MAILCHIMP_AUDIENCE_ID and MAILCHIMP_SERVER_PREFIX)

def _mc_require():
    if not _mailchimp_enabled():
        raise ValueError("Mailchimp not configured. Set MAILCHIMP_API_KEY, MAILCHIMP_AUDIENCE_ID, MAILCHIMP_SERVER_PREFIX.")

def mc_request(method: str, path: str, *, params=None, json_body=None, timeout=25):
    """
    Mailchimp Marketing API request helper.
    Uses HTTP Basic auth: username can be anything, password is API key.
    """
    _mc_require()
    url = f"{MAILCHIMP_BASE_URL}{path}"

    # g may not exist in some contexts
    rid = "-"
    try:
        rid = getattr(g, "_rid", "-")
    except Exception:
        pass

    log.info(f"[{rid}] mailchimp {method.upper()} {path}")

    r = requests.request(
        method=method.upper(),
        url=url,
        params=params,
        json=json_body,
        auth=("anystring", MAILCHIMP_API_KEY),
        timeout=timeout,
    )

    text = r.text or ""
    if r.status_code >= 400:
        detail = text
        try:
            j = r.json()
            detail = j.get("detail") or j.get("title") or detail
            # ✅ Mailchimp often includes exact bad fields here:
            # e.g. [{"field":"merge_fields.FNAME","message":"This field is required."}]
            if j.get("errors"):
                detail = f"{detail} | errors={j.get('errors')}"
        except Exception:
            pass
        raise ValueError(f"mailchimp {r.status_code}: {detail}")

    if not text.strip():
        return {}
    try:
        return r.json()
    except Exception:
        return {"raw": text}


def mc_subscriber_hash(email: str) -> str:
    return hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()
def mc_format_phone(raw: str | None) -> str | None:
    """
    Mailchimp PHONE merge field expects: (###) ### - ####
    """
    digits = re.sub(r"\D", "", raw or "")
    if len(digits) == 10:
        return f"({digits[0:3]}) {digits[3:6]} - {digits[6:10]}"
    return None

def mc_format_birthday(raw: str | None) -> str | None:
    """
    Mailchimp BIRTHDAY merge field expects: MM/DD
    Accepts: MM/DD or ISO dates like YYYY-MM-DD (or ISO datetime).
    """
    if not raw:
        return None
    s = str(raw).strip()

    # already in MM/DD
    if re.fullmatch(r"\d{2}/\d{2}", s):
        return s

    # try ISO date/datetime
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return dt.strftime("%m/%d")
    except Exception:
        return None

def mc_upsert_member(
    email: str,
    first_name: str | None = None,
    last_name: str | None = None,
    phone: str | None = None,
    birthday: str | None = None,
):
    """
    Add or update a list member (idempotent).
    Uses status_if_new so we do NOT override unsubscribed users.
    """
    em = (email or "").strip()
    if not em:
        raise ValueError("email required")

    h = mc_subscriber_hash(em)

    fn = (first_name or "").strip()
    ln = (last_name or "").strip()

    merge: dict = {}

    # If you marked FNAME/LNAME as REQUIRED in Mailchimp, uncomment these:
    # if not fn: fn = "Member"
    # if not ln: ln = ""

    if fn:
        merge["FNAME"] = fn[:80]
    if ln:
        merge["LNAME"] = ln[:80]

    ph = mc_format_phone(phone)
    if ph:
        merge["PHONE"] = ph

    bday = mc_format_birthday(birthday)
    if bday:
        merge["BIRTHDAY"] = bday

    body = {
        "email_address": em,
        "status_if_new": "subscribed",
    }

    # ✅ don’t send merge_fields: {} (can trigger “invalid merge fields” on some lists)
    if merge:
        body["merge_fields"] = merge

    return mc_request("PUT", f"/lists/{MAILCHIMP_AUDIENCE_ID}/members/{h}", json_body=body)

def _to_simple_html(subject: str, message: str) -> str:
    """
    Create safe, simple HTML content + includes unsubscribe merge tag.
    Mailchimp typically requires an unsubscribe link in campaigns.
    """
    safe_subject = html_lib.escape(subject or "")
    safe_message = html_lib.escape(message or "").replace("\n", "<br/>")

    return f"""
<!doctype html>
<html>
  <body style="font-family: Arial, sans-serif; line-height: 1.45;">
    <h2>{safe_subject}</h2>
    <div>{safe_message}</div>
    <hr/>
    <p style="font-size:12px;color:#666;">
      You can unsubscribe anytime:
      <a href="*|UNSUB|*">Unsubscribe</a>
    </p>
  </body>
</html>
""".strip()

def mc_create_campaign(subject: str, *, segment_id: int | None = None, from_name: str | None = None, reply_to: str | None = None):
    """
    Create a campaign that targets either:
      - the whole audience (segment_id=None)
      - a saved segment (segment_id provided)
    """
    from_name = (from_name or MAILCHIMP_FROM_NAME).strip()
    reply_to = (reply_to or MAILCHIMP_REPLY_TO).strip()

    recipients = {"list_id": MAILCHIMP_AUDIENCE_ID}
    if segment_id is not None:
        # recipients.segment_opts.saved_segment_id is the usual way to target a segment :contentReference[oaicite:4]{index=4}
        recipients["segment_opts"] = {"saved_segment_id": int(segment_id)}

    payload = {
        "type": "regular",
        "recipients": recipients,
        "settings": {
            "subject_line": subject,
            "title": f"{subject} ({datetime.now(timezone.utc).isoformat()})",
            "from_name": from_name,
            "reply_to": reply_to,
        },
    }

    # POST /campaigns :contentReference[oaicite:5]{index=5}
    return mc_request("POST", "/campaigns", json_body=payload)

def mc_set_campaign_content(campaign_id: str, subject: str, message: str):
    html_body = _to_simple_html(subject, message)
    payload = {"html": html_body}

    # PUT /campaigns/{campaign_id}/content :contentReference[oaicite:6]{index=6}
    return mc_request("PUT", f"/campaigns/{campaign_id}/content", json_body=payload)

def mc_send_campaign(campaign_id: str):
    # POST /campaigns/{campaign_id}/actions/send :contentReference[oaicite:7]{index=7}
    return mc_request("POST", f"/campaigns/{campaign_id}/actions/send")

def mc_create_static_segment(name: str, emails: list[str]) -> int:
    """
    Try creating a static segment with emails in one shot.
    If Mailchimp rejects the payload (API differences/accounts), fallback to:
      - create empty segment
      - add members via segment members endpoint
    """
    emails = [e.strip() for e in emails if e and e.strip()]
    if not emails:
        raise ValueError("No emails provided for segment")

    try:
        # POST /lists/{list_id}/segments :contentReference[oaicite:8]{index=8}
        seg = mc_request("POST", f"/lists/{MAILCHIMP_AUDIENCE_ID}/segments", json_body={
            "name": name,
            "static_segment": emails,
        })
        return int(seg["id"])
    except Exception:
        # fallback: create empty segment then add members
        seg = mc_request("POST", f"/lists/{MAILCHIMP_AUDIENCE_ID}/segments", json_body={"name": name})
        seg_id = int(seg["id"])

        # Add members to segment (best-effort) :contentReference[oaicite:9]{index=9}
        for e in emails:
            try:
                mc_request("POST", f"/lists/{MAILCHIMP_AUDIENCE_ID}/segments/{seg_id}/members", json_body={"email_address": e}, timeout=15)
            except Exception as ex:
                log.warning(f"[{getattr(g, '_rid', '-')}] segment add member failed {e}: {str(ex)[:160]}")
        return seg_id

def mc_delete_segment(seg_id: int):
    try:
        mc_request("DELETE", f"/lists/{MAILCHIMP_AUDIENCE_ID}/segments/{int(seg_id)}", timeout=15)
    except Exception:
        pass

stripe.api_key = STRIPE_SECRET_KEY

# Secret for QR token signing
CHECKIN_QR_SECRET = os.getenv("CHECKIN_QR_SECRET")
if not CHECKIN_QR_SECRET:
    logging.getLogger("api").warning("CHECKIN_QR_SECRET not set; using weak dev secret")
    CHECKIN_QR_SECRET = "dev-qr-secret"

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
CORS_ORIGINS = ["http://localhost:3000", "http://localhost:5173", "https://showtime-front-end.vercel.app","https://www.showtimeboxinggym.com", FRONTEND_URL]
CORS(
    app,
    resources={r"/(signup|login|api/.*|ping|webhooks/.*)": {"origins": CORS_ORIGINS}},
    supports_credentials=True,
    allow_headers=["Content-Type", "Authorization", "x-request-id", "Stripe-Signature"],
    expose_headers=["x-request-id"],
)


def err(msg, code=400):
    log.warning(f"ERR {code}: {msg}")
    return make_response({"error": str(msg)}, code)

app.register_blueprint(admin_bp, url_prefix='/api/admin')
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
    rid = g.get("_rid", "-")
    log.info(f"[{rid}] ← {resp.status_code} {resp.content_type} {dur_ms:.1f}ms")
    # Attach request id so the frontend can surface it
    try:
        resp.headers["x-request-id"] = rid
    except Exception:
        pass
    return resp



@app.errorhandler(Exception)
def _unhandled(e):
    rid = g.get("_rid", "-")
    if isinstance(e, HTTPException):
        # Preserve real HTTP codes (e.g., 404) instead of turning them into 500s
        log.warning(f"[{rid}] http {e.code}: {e.description}")
        return make_response({"error": e.description}, e.code)
    log.error(f"[{rid}] !!! {type(e).__name__}: {e}\n{traceback.format_exc()}")
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


def _parse_ts(s: str) -> datetime:
    """Tolerant ISO8601 parser (supports trailing 'Z')."""
    if isinstance(s, datetime):
        return s
    return datetime.fromisoformat(str(s).replace("Z", "+00:00"))

# ───────── NEW: base64url helper that tolerates missing padding ─────────
def _urlsafe_b64decode(s: str) -> bytes:
    s = (s or "").strip()
    if not s:
        return b""
    # add required '=' padding
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))

# ───────────────────────── check-ins: QR token ─────────────────────
def _sign_qr_token(user_id: str, exp_ts: int) -> str:
    """
    Create a compact token: base64url("user.exp.sig")
    where sig = HMAC-SHA256(key=CHECKIN_QR_SECRET, msg="user.exp").
    """
    msg = f"{user_id}.{exp_ts}".encode("utf-8")
    sig = hmac.new(CHECKIN_QR_SECRET.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    raw = f"{user_id}.{exp_ts}.{sig}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")

# ───────── NEW: verify token accepting several historical shapes ─────────
def _verify_qr_token(token: str) -> tuple[str, int]:
    """
    Accepts tokens in any of these shapes and returns (user_id, exp_ts):
      A) base64url("user_id.exp.sigHex")           ← current minted format
      B) "user_id.exp.sigHex"                      ← raw dotted form
      C) base64(user_id).base64(exp or .exp.).base64(sigHex)  ← legacy 3-part
    Raises ValueError on failure.
    """
    now = int(datetime.now(timezone.utc).timestamp())

    def _validate(user_id: str, exp_str: str, sig_hex: str):
        if not user_id or not exp_str or not sig_hex:
            raise ValueError("malformed token")
        try:
            exp = int(str(exp_str).strip().strip("."))
        except Exception:
            raise ValueError("invalid expiry")
        msg = f"{user_id}.{exp}".encode("utf-8")
        expected = hmac.new(CHECKIN_QR_SECRET.encode("utf-8"), msg, hashlib.sha256).hexdigest()
        # use constant-time comparison
        if not hmac.compare_digest(expected, sig_hex):
            raise ValueError("bad signature")
        if exp < now:
            raise ValueError("token expired")
        return user_id, exp

    tok = (token or "").strip()

    # 1) Attempt full base64url of "user.exp.sigHex"
    try:
        raw = _urlsafe_b64decode(tok).decode("utf-8")
        parts = raw.split(".", 2)
        if len(parts) == 3:
            return _validate(parts[0], parts[1], parts[2])
    except Exception:
        pass

    # 2) Attempt legacy three-part base64(user).base64(exp-ish).base64(sig)
    if tok.count(".") >= 2:
        p = tok.split(".")
        # try first three segments only
        try:
            u = _urlsafe_b64decode(p[0]).decode("utf-8")
            mid = _urlsafe_b64decode(p[1]).decode("utf-8")  # might be ".12345." or "12345"
            s = _urlsafe_b64decode(p[2]).decode("utf-8")
            return _validate(u, mid, s)
        except Exception:
            # fallthrough
            pass

    # 3) Attempt raw "user.exp.sigHex"
    if tok.count(".") >= 2:
        try:
            parts = tok.split(".", 2)
            return _validate(parts[0], parts[1], parts[2])
        except Exception:
            pass

    raise ValueError("invalid token")

@app.get("/api/checkins/qr-token")
@auth_required
def get_qr_token():
    # ttl query param (seconds); clamp to a safe range
    try:
        ttl = int(request.args.get("ttl", "300"))
    except Exception:
        ttl = 300
    ttl = max(30, min(ttl, 1800))  # 30s .. 30min

    exp_ts = int((datetime.now(timezone.utc) + timedelta(seconds=ttl)).timestamp())
    token = _sign_qr_token(g.user_id, exp_ts)
    return jsonify({"token": token, "expires_at": exp_ts})

def parse_data_url_png(data_url: str) -> bytes:
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
    return datetime.fromtimestamp(int(sec), tz=timezone.utc)

def add_interval(dt: datetime, interval: str, count: int) -> datetime:
    """Add a plan interval to a datetime (supports day/week/month/year)."""
    interval = (interval or "").lower()
    count = int(count or 1)
    if interval == "day":
        return dt + timedelta(days=count)
    if interval == "week":
        return dt + timedelta(weeks=count)
    if interval == "month":
        month0 = dt.month - 1 + count
        year = dt.year + month0 // 12
        month = month0 % 12 + 1
        day = min(dt.day, calendar.monthrange(year, month)[1])
        return dt.replace(year=year, month=month, day=day)
    if interval == "year":
        try:
            return dt.replace(year=dt.year + count)
        except ValueError:
            return dt.replace(month=2, day=28, year=dt.year + count)
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
def _stripe_dashboard_base() -> str:
    # If you're using a test secret key, use the /test dashboard path
    key = (STRIPE_SECRET_KEY or "").strip()
    if key.startswith("sk_test_"):
        return "https://dashboard.stripe.com/test"
    return "https://dashboard.stripe.com"

def stripe_customer_dashboard_url(customer_id: str | None) -> str | None:
    if not customer_id:
        return None
    return f"https://dashboard.stripe.com/customers/{customer_id}"
def ensure_one_time_period_from_meta(
    meta: dict,
    *,
    external_id: str,
    created_ts: int | None,
    amount_total: int | None,
    currency: str | None,
) -> tuple[dict, bool]:
    plan_id = (meta.get("plan_id") or "").strip()
    owner_user_id = (meta.get("owner_user_id") or "").strip()
    subject_user_id = (meta.get("subject_user_id") or "").strip() or None
    dependent_id = (meta.get("dependent_id") or "").strip() or None

    if not (plan_id and owner_user_id):
        raise ValueError("session metadata missing plan_id or owner_user_id")

    # Load plan
    plan_rows = (
        sb_admin.table("membership_plans")
        .select("id,interval,interval_count")
        .eq("id", plan_id)
        .limit(1)
        .execute()
        .data
    )
    if not plan_rows:
        raise ValueError("plan not found")
    plan = plan_rows[0]

    # If no dependent id, default subject to the owner
    subject_uid = subject_user_id or (owner_user_id if not dependent_id else None)

    mem = ensure_membership(
        owner_user_id=owner_user_id,
        plan_id=plan_id,
        subject_user_id=subject_uid,
        dependent_id=dependent_id,
        status="active",
    )

    # Idempotency: period already created for this checkout session?
    exists = (
        sb_admin.table("membership_periods")
        .select("id")
        .eq("source", "stripe")
        .eq("source_ref", external_id)
        .limit(1)
        .execute()
        .data
    )

    created_period = False
    if not exists:
        start = to_utc_ts(created_ts) if created_ts else datetime.now(timezone.utc)
        end = add_interval(start, plan.get("interval") or "day", plan.get("interval_count") or 1)

        sb_admin.table("membership_periods").insert(
            {
                "user_membership_id": mem["id"],
                "owner_user_id": mem["owner_user_id"],
                "subject_user_id": mem.get("subject_user_id"),
                "dependent_id": mem.get("dependent_id"),
                "plan_id": mem["plan_id"],
                "source": "stripe",
                "source_ref": external_id,
                "period_start": start,
                "period_end": end,
            }
        ).execute()
        created_period = True

    # Optional receipt (idempotent)
    if amount_total is not None:
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
            sb_admin.table("payment_receipts").insert(
                {
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
                }
            ).execute()

    # Keep membership active
    sb_admin.table("user_memberships").update({"status": "active"}).eq("id", mem["id"]).execute()

    return mem, created_period

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
    """Return True if there's no required waiver OR the subject signed the current version."""
    rid = getattr(g, "_rid", "-")
    log.info(f"[{rid}] WAIVER_CHECK start subject_type={subject_type} subject_id={subject_id}")

    waivers = (
        sb_admin.table("waivers")
        .select("id,version,required_for_purchase,is_active")
        .eq("is_active", True)
        .eq("required_for_purchase", True)
        .limit(1)
        .execute()
        .data
    )
    if not waivers:
        log.info(f"[{rid}] WAIVER_CHECK no active + required waiver → allow purchase")
        return True

    w = waivers[0]
    log.info(
        f"[{rid}] WAIVER_CHECK active waiver id={w['id']} version={w['version']} required={w['required_for_purchase']}"
    )

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

    rows = q.limit(2).execute().data
    signed = bool(rows)
    log.info(f"[{rid}] WAIVER_CHECK signed={signed} matching_signatures={len(rows)}")
    return signed

# ───────── helpers for access + check-ins ────────────
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
            ps = _parse_ts(r["period_start"])
            pe = _parse_ts(r["period_end"])
            if ps <= now < pe:
                return True
        except Exception:
            continue
    return False

def record_checkin(
    *, subject_type: str, subject_id: str, method: str = "qr", location: str | None = None, source: str | None = None, meta: dict | None = None
) -> dict:
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

# ───────────────────────── root + health ───────────────────────────
@app.get("/")
def root():
    return jsonify({"ok": True, "service": "showtime-backend", "time": datetime.now(timezone.utc).isoformat()})

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
        res = sb_admin.auth.admin.create_user({"email": email, "password": password, "email_confirm": True})
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

# Legacy guard: block any old endpoint that could bypass waiver
@app.post("/api/create-checkout-session")
@auth_required
def legacy_checkout_block():
    return err("This endpoint is deprecated. Use /api/checkout/session.", 410)
@app.post("/api/auth/refresh")
def auth_refresh():
    """
    Body: { "refresh_token": "..." }
    Returns same shape as /login:
      { access_token, refresh_token, user_id, expires_in, token_type }
    """
    body = request.get_json(force=True, silent=True) or {}
    refresh_token = (body.get("refresh_token") or "").strip()
    if not refresh_token:
        return err("refresh_token required", 400)

    try:
        # supabase-py typically returns an object similar to sign_in_with_password
        res = sb_public.auth.refresh_session(refresh_token)
        session = res.session
        user = res.user
        return jsonify({
            "access_token": session.access_token,
            "refresh_token": session.refresh_token,
            "user_id": user.id,
            "expires_in": session.expires_in,
            "token_type": session.token_type,
        })
    except Exception as e:
        return err(f"refresh failed: {e}", 401)

# ───────────────────────── profiles / plans ────────────────────────
@app.get("/api/profile/me")
@auth_required
def profile_me():
    rows = sb_admin.table("user_profiles").select("*").eq("user_id", g.user_id).limit(1).execute().data
    if not rows:
        return err("profile not found", 404)
    log.info(f"[{g._rid}] profile_me user_id={g.user_id}")
    return jsonify(rows[0])

@app.get("/api/plans")
def list_plans():
    """Public: list active plans (includes slug & checkout mode)."""
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
    rid = getattr(g, "_rid", "-")
    subject_type = (request.args.get("subjectType") or "user").lower()
    subject_id = request.args.get("subjectId")
    log.info(f"[{rid}] /api/waivers/active subject_type={subject_type} subject_id={subject_id} user_id={g.user_id}")

    if subject_type not in ("user", "dependent"):
        return err("subjectType must be 'user' or 'dependent'", 400)
    if subject_type == "user":
        subject_id = g.user_id
    elif not subject_id:
        return err("subjectId required for dependent", 400)

    waivers = (
        sb_admin.table("waivers")
        .select("id,slug,version,title,hash,is_active,required_for_purchase")
        .eq("is_active", True)
        .eq("required_for_purchase", True)
        .limit(1)
        .execute()
        .data
    )
    if not waivers:
        log.info(f"[{rid}] /api/waivers/active none-found (is_active=true & required_for_purchase=true)")
        return jsonify({"waiver": None, "signed": False})

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
    sigs = q.limit(2).execute().data
    signed = bool(sigs)

    log.info(f"[{rid}] /api/waivers/active found id={w['id']} version={w['version']} signed={signed} sig_count={len(sigs)}")
    return jsonify({"waiver": w, "signed": signed})

@app.post("/api/waivers/sign")
@auth_required
def waiver_sign():
    rid = getattr(g, "_rid", "-")
    body = request.get_json(force=True, silent=True) or {}
    subject_type = (body.get("subject_type") or "user").lower()
    subject_id = body.get("subject_id")

    log.info(f"[{rid}] /api/waivers/sign start subject_type={subject_type} subject_id={subject_id} signer={g.user_id}")

    if subject_type not in ("user", "dependent"):
        return err("subject_type must be 'user' or 'dependent'", 400)
    if subject_type == "user":
        subject_id = g.user_id
    elif not subject_id:
        return err("subject_id required for dependent", 400)

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
        log.info(f"[{rid}] /api/waivers/sign no active required waiver")
        return err("no active waiver to sign", 400)
    w = waivers[0]

    sig_data_url = body.get("signature_data_url")
    sig_png_bytes = b""
    if sig_data_url:
        try:
            sig_png_bytes = parse_data_url_png(sig_data_url)
        except Exception as e:
            log.warning(f"[{rid}] /api/waivers/sign parse signature_data_url failed: {e}")

    payload = {
        "waiver_id": w["id"],
        "waiver_version": w["version"],
        "signed_by_user_id": g.user_id,
        "relationship_to_subject": body.get("relationship_to_subject"),
        "full_name": body.get("full_name"),
        "date_of_birth": body.get("date_of_birth"),
        "signature_svg": body.get("signature_svg"),
        "signature_image_url": None,
        "pdf_url": None,
        "ip_address": request.remote_addr,
        "user_agent": request.headers.get("User-Agent"),
    }
    if subject_type == "user":
        payload["subject_user_id"] = subject_id
    else:
        payload["dependent_id"] = subject_id

    log.info(f"[{rid}] /api/waivers/sign inserting sig row (png_bytes={len(sig_png_bytes)})")

    try:
        sig = sb_admin.table("waiver_signatures").insert(payload).execute().data[0]
        sig_id = sig["id"]
    except Exception as e:
        log.error(f"[{rid}] /api/waivers/sign insert failed: {e}")
        return err(f"sign insert failed: {e}", 400)

    ensure_bucket(WAIVER_BUCKET)
    signed_at = datetime.now(timezone.utc)

    try:
        sig_url = None
        if sig_png_bytes:
            sig_path = f"signatures/{sig_id}.png"
            log.info(f"[{rid}] [storage] upload signature {sig_path} bytes={len(sig_png_bytes)}")
            sb_admin.storage.from_(WAIVER_BUCKET).upload(
                sig_path, sig_png_bytes, {"content-type": "image/png", "upsert": True}
            )
            sig_url = sb_admin.storage.from_(WAIVER_BUCKET).get_public_url(sig_path).get("publicURL")

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
        log.info(f"[{rid}] [storage] upload pdf {pdf_path} bytes={len(pdf_bytes)}")
        sb_admin.storage.from_(WAIVER_BUCKET).upload(
            pdf_path, pdf_bytes, {"content-type": "application/pdf", "upsert": True}
        )
        pdf_url = sb_admin.storage.from_(WAIVER_BUCKET).get_public_url(pdf_path).get("publicURL")

        sig = (
            sb_admin.table("waiver_signatures")
            .update({"signature_image_url": sig_url, "pdf_url": pdf_url})
            .eq("id", sig_id)
            .execute()
            .data[0]
        )
        log.info(f"[{rid}] /api/waivers/sign completed sig_id={sig_id}")
    except Exception as e:
        log.warning(f"[{rid}] /api/waivers/sign asset upload failed: {e}")

    if subject_type == "user":
        try:
            sb_admin.table("user_profiles").update({"signed_waiver": True}).eq("user_id", subject_id).execute()
        except Exception:
            pass

    return jsonify(sig), 201

# ───────────────────────── checkout: session info ──────────────────
@app.get("/api/checkout/session-info")
@auth_required
def checkout_session_info():
    """
    Return a minimal, auth-checked summary about a Stripe Checkout Session so
    the frontend can show 'what you just bought'.
    Query: ?session_id=cs_...
    """
    sid = (request.args.get("session_id") or "").strip()
    if not sid:
        return err("session_id required", 400)

    try:
        sess = stripe.checkout.Session.retrieve(sid)
    except Exception as e:
        return err(f"invalid session_id: {e}", 400)

    # Verify the session belongs to the caller using metadata we set at creation.
    md = (sess.get("metadata") or {}) if isinstance(sess, dict) else getattr(sess, "metadata", {}) or {}
    owner_user_id = md.get("owner_user_id")
    if owner_user_id and owner_user_id != g.user_id:
        return err("forbidden", 403)

    plan_id = md.get("plan_id")
    plan = None
    if plan_id:
        rows = (
            sb_admin.table("membership_plans")
            .select("id,name,price_cents,currency,interval,interval_count")
            .eq("id", plan_id)
            .limit(1)
            .execute()
            .data
        )
        plan = rows[0] if rows else None

    # Subject label
    subj_type = "user"
    subj_id = md.get("subject_user_id") or None
    if not subj_id:
        subj_type = "dependent"
        subj_id = md.get("dependent_id")
    subject_label = "Me"
    if subj_type == "dependent" and subj_id:
        dep_rows = (
            sb_admin.table("dependents")
            .select("first_name,last_name")
            .eq("id", subj_id)
            .limit(1)
            .execute()
            .data
        )
        if dep_rows:
            fn = (dep_rows[0].get("first_name") or "").strip()
            ln = (dep_rows[0].get("last_name") or "").strip()
            subject_label = (fn + " " + ln).strip() or "Dependent"

    out = {
        "mode": sess.get("mode"),
        "status": sess.get("status"),
        "amount_total": sess.get("amount_total"),
        "currency": (sess.get("currency") or "usd").upper(),
        "plan": plan,  # may be None if plan couldn’t be looked up
        "subject": {"type": subj_type, "id": subj_id, "label": subject_label},
    }
    return jsonify(out)
@app.post("/api/checkout/finalize")
@auth_required
def checkout_finalize():
    if not STRIPE_SECRET_KEY:
        return err("stripe not configured", 500)

    body = request.get_json(force=True, silent=True) or {}
    sid = (body.get("session_id") or body.get("sessionId") or "").strip()
    if not sid:
        return err("session_id required", 400)

    try:
        sess = stripe.checkout.Session.retrieve(sid)
    except Exception as e:
        return err(f"invalid session_id: {e}", 400)

    md = sess.get("metadata", {}) or {}
    owner_user_id = (md.get("owner_user_id") or "").strip()

    # Security: only the owner can finalize their checkout
    if not owner_user_id or owner_user_id != g.user_id:
        return err("forbidden", 403)

    # Only finalize completed sessions
    if sess.get("status") != "complete" and sess.get("payment_status") != "paid":
        return err("checkout session not complete yet", 409)

    mode = (sess.get("mode") or "").lower()
    customer_id = sess.get("customer")
    plan_id = (md.get("plan_id") or "").strip()
    if not plan_id:
        return err("missing plan_id in session metadata", 400)

    subject_user_id = (md.get("subject_user_id") or "").strip() or None
    dependent_id = (md.get("dependent_id") or "").strip() or None
    if not subject_user_id and not dependent_id:
        subject_user_id = owner_user_id

    # --- Subscription checkout
    if mode == "subscription":
        sub_id = sess.get("subscription")
        if not sub_id:
            return err("subscription missing on session", 400)

        try:
            sub = stripe.Subscription.retrieve(sub_id)
        except Exception as e:
            return err(f"could not retrieve subscription: {e}", 400)

        sub_status = (sub.get("status") or "").lower()
        # Keep mapping consistent with your other logic
        mapped_status = (
            "active" if sub_status in ("active", "trialing")
            else "past_due" if sub_status in ("past_due", "incomplete", "unpaid", "paused")
            else "canceled" if sub_status in ("canceled", "incomplete_expired")
            else "past_due"
        )

        mem = ensure_membership(
            owner_user_id=owner_user_id,
            plan_id=plan_id,
            subject_user_id=subject_user_id,
            dependent_id=dependent_id,
            provider_customer_id=customer_id,
            provider_subscription_id=sub_id,
            status=mapped_status,
        )

        created_period = False
        start_ts = sub.get("current_period_start")
        end_ts = sub.get("current_period_end")
        if start_ts and end_ts:
            src_ref = f"{sub_id}:{int(start_ts)}"
            exists = (
                sb_admin.table("membership_periods")
                .select("id")
                .eq("source", "stripe")
                .eq("source_ref", src_ref)
                .limit(1)
                .execute()
                .data
            )
            if not exists:
                sb_admin.table("membership_periods").insert(
                    {
                        "user_membership_id": mem["id"],
                        "owner_user_id": mem["owner_user_id"],
                        "subject_user_id": mem.get("subject_user_id"),
                        "dependent_id": mem.get("dependent_id"),
                        "plan_id": mem["plan_id"],
                        "source": "stripe",
                        "source_ref": src_ref,
                        "period_start": to_utc_ts(int(start_ts)),
                        "period_end": to_utc_ts(int(end_ts)),
                    }
                ).execute()
                created_period = True

        sb_admin.table("user_memberships").update({"status": mapped_status}).eq("id", mem["id"]).execute()

        return jsonify(
            {
                "ok": True,
                "mode": "subscription",
                "membership_id": mem["id"],
                "status": mapped_status,
                "customer_id": customer_id,
                "subscription_id": sub_id,
                "period_backfilled": created_period,
            }
        )

    # --- One-time payment checkout
    if mode == "payment":
        amount_total = sess.get("amount_total")
        currency = sess.get("currency")
        created_ts = sess.get("created")
        external_id = sess.get("id")

        try:
            mem, created_period = ensure_one_time_period_from_meta(
                md,
                external_id=external_id,
                created_ts=created_ts,
                amount_total=amount_total,
                currency=currency,
            )
        except Exception as e:
            return err(f"finalize failed: {e}", 400)

        return jsonify(
            {
                "ok": True,
                "mode": "payment",
                "membership_id": mem["id"],
                "status": "active",
                "customer_id": customer_id,
                "subscription_id": None,
                "period_backfilled": created_period,
            }
        )

    return err("unsupported checkout mode", 400)


# ───────────────────────── checkout/session ────────────────────────
@app.post("/api/checkout/session")
@auth_required
def create_checkout_session():
    rid = getattr(g, "_rid", "-")
    if not STRIPE_SECRET_KEY:
        return err("stripe not configured", 500)

    body = request.get_json(force=True, silent=True) or {}
    plan_id = body.get("plan_id")
    plan_slug = body.get("plan_slug")
    subject_type = (body.get("subject_type") or "user").lower()
    subject_id = body.get("subject_id")

    log.info(
        f"[{rid}] /api/checkout/session start subject_type={subject_type} body_subject_id={subject_id} "
        f"owner={g.user_id} plan_id={plan_id} plan_slug={plan_slug}"
    )

    if subject_type not in ("user", "dependent"):
        return err("subject_type must be 'user' or 'dependent'", 400)
    if subject_type == "user":
        subject_id = g.user_id
    elif not subject_id:
        return err("subject_id required for dependent", 400)

    # Enforce waiver before starting Stripe checkout
    signed_ok = has_signed_required_waiver(subject_type, subject_id)
    log.info(f"[{rid}] /api/checkout/session waiver_enforced signed_ok={signed_ok}")
    if not signed_ok:
        return err("You must sign the current waiver before purchasing.", 400)

    if plan_id:
        sel = sb_admin.table("membership_plans").select("*").eq("id", plan_id).eq("is_active", True).limit(1)
    elif plan_slug:
        sel = sb_admin.table("membership_plans").select("*").eq("slug", plan_slug).eq("is_active", True).limit(1)
    else:
        return err("plan_id or plan_slug required", 400)

    plans = sel.execute().data
    if not plans:
        log.info(f"[{rid}] /api/checkout/session plan not found or inactive")
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

    base = FRONTEND_URL or "http://localhost:5173"
    success_url = f"{base}/purchase?session_id={{CHECKOUT_SESSION_ID}}"
    cancel_url = f"{base}/purchase"

    log.info(
        f"[{rid}] /api/checkout/session creating stripe session mode={checkout_mode} "
        f"customer={customer_id} price={price_id} plan={plan['id']} subject_id={subject_id}"
    )

    try:
        if checkout_mode == "subscription":
            sess = stripe.checkout.Session.create(
                mode="subscription",
                line_items=[{"price": price_id, "quantity": 1}],
                customer=customer_id,
                success_url=success_url,
                cancel_url=cancel_url,
                metadata=md,
                subscription_data={"metadata": md},
            )
        else:
            sess = stripe.checkout.Session.create(
                mode="payment",
                line_items=[{"price": price_id, "quantity": 1}],
                customer=customer_id,
                success_url=success_url,
                cancel_url=cancel_url,
                metadata=md,
            )
        log.info(f"[{rid}] /api/checkout/session created id={sess.id}")
    except Exception as e:
        log.error(f"[{rid}] /api/checkout/session stripe error: {e}")
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

    def _ensure_one_time_period(meta: dict, amount_total: int | None, currency: str | None, external_id: str | None, created_ts: int | None):
        plan_id = meta.get("plan_id")
        owner_user_id = meta.get("owner_user_id")
        subject_user_id = meta.get("subject_user_id") or None
        dependent_id = meta.get("dependent_id") or None

        if not (plan_id and owner_user_id):
            return

        # Load plan
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

        # Membership for subject
        subject_uid = subject_user_id if subject_user_id else (owner_user_id if not dependent_id else None)
        mem = ensure_membership(
            owner_user_id=owner_user_id,
            plan_id=plan_id,
            subject_user_id=subject_uid,
            dependent_id=dependent_id,
            status="active",
        )

        # Idempotency on external id
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

        sb_admin.table("membership_periods").insert(
            {
                "user_membership_id": mem["id"],
                "owner_user_id": mem["owner_user_id"],
                "subject_user_id": mem.get("subject_user_id"),
                "dependent_id": mem.get("dependent_id"),
                "plan_id": mem["plan_id"],
                "source": "stripe",
                "source_ref": external_id,
                "period_start": start,
                "period_end": end,
            }
        ).execute()

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
                sb_admin.table("payment_receipts").insert(
                    {
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
                    }
                ).execute()

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

        log.info(
            f"checkout.completed mode={mode} cust={customer_id} owner={owner_user_id} plan={plan_id} "
            f"subj={subject_user_id} dep={dependent_id}"
        )

        if mode == "subscription":
            sub_id = sess.get("subscription")
            if not (plan_id and owner_user_id and sub_id and customer_id):
                return jsonify({"ok": True})

            # Ensure membership row and seed current period immediately (idempotent)
            mem = ensure_membership(
                owner_user_id=owner_user_id,
                plan_id=plan_id,
                subject_user_id=subject_user_id,
                dependent_id=dependent_id,
                provider_customer_id=customer_id,
                provider_subscription_id=sub_id,
                status="active",
            )

            try:
                sub = stripe.Subscription.retrieve(sub_id)
                start_ts = sub.get("current_period_start")
                end_ts = sub.get("current_period_end")
                if start_ts and end_ts:
                    src_ref = f"{sub_id}:{start_ts}"
                    exists = (
                        sb_admin.table("membership_periods")
                        .select("id")
                        .eq("source", "stripe")
                        .eq("source_ref", src_ref)
                        .limit(1)
                        .execute()
                        .data
                    )
                    if not exists:
                        sb_admin.table("membership_periods").insert({
                            "user_membership_id": mem["id"],
                            "owner_user_id": mem["owner_user_id"],
                            "subject_user_id": mem.get("subject_user_id"),
                            "dependent_id": mem.get("dependent_id"),
                            "plan_id": mem["plan_id"],
                            "source": "stripe",
                            "source_ref": src_ref,
                            "period_start": to_utc_ts(int(start_ts)),
                            "period_end": to_utc_ts(int(end_ts)),
                        }).execute()
            except Exception as e:
                log.warning(f"could not seed period from subscription: {e}")

            return jsonify({"ok": True})

        # One-time payment: grant access period
        if mode == "payment":
            amount_total = sess.get("amount_total")
            currency = sess.get("currency")
            created_ts = sess.get("created")
            external_id = sess.get("id")
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

# ───────── NEW: public scan endpoint (verifies token + records check-in) ─────────
@app.post("/api/checkins/scan")
def public_qr_scan():
    body = request.get_json(force=True, silent=True) or {}
    token = (body.get("token") or "").strip()
    location = body.get("location")
    source = body.get("source")

    if not token:
        return err("token required", 400)

    rid = getattr(g, "_rid", uuid4().hex[:8])

    try:
        user_id, exp_ts = _verify_qr_token(token)
        log.info(f"[{rid}] scan token verified user={user_id} exp={exp_ts}")
    except ValueError as e:
        return err(str(e), 400)
    except Exception as e:
        log.error(f"[{rid}] scan verify error: {e}")
        return err("verification failed", 400)

    # 1) Fast DB check
    had_access_before = has_access_now_for_subject(user_id, None)

    sync_info = None
    # 2) Only if denied, do a throttled Stripe sync
    if not had_access_before:
        try:
            sync_info = sync_stripe_for_user(user_id, min_age_seconds=300, force=False)
        except Exception as e:
            log.warning(f"[{rid}] checkin fallback sync failed: {str(e)[:200]}")
            sync_info = {"ok": False, "error": "sync failed"}

    # 3) Re-check after sync attempt
    has_access_after = has_access_now_for_subject(user_id, None)

    # 4) Record the check-in AFTER the sync/recheck so rec.has_access_now is accurate
    rec = record_checkin(
        subject_type="user",
        subject_id=user_id,
        method="qr",
        location=location,
        source=source,
        meta={
            "exp": exp_ts,
            "access_before": had_access_before,
            "access_after": has_access_after,
            "sync": {
                "ok": sync_info.get("ok") if isinstance(sync_info, dict) else None,
                "skipped": sync_info.get("skipped") if isinstance(sync_info, dict) else None,
                "reason": sync_info.get("reason") if isinstance(sync_info, dict) else None,
            } if sync_info else None,
        },
    )

    # Fetch user display info (optional)
    user = {}
    try:
        prof = (
            sb_admin.table("user_profiles")
            .select("first_name,last_name,email")
            .eq("user_id", user_id)
            .limit(1)
            .execute()
            .data
        )
        if prof:
            user = {
                "first_name": prof[0].get("first_name"),
                "last_name": prof[0].get("last_name"),
                "email": prof[0].get("email"),
            }
    except Exception:
        pass

    return jsonify({"ok": True, "checkin": rec, "user": user, "sync": sync_info})


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

    rows = q.execute().data or []
    can_enter = any(_parse_ts(r["period_start"]) <= now < _parse_ts(r["period_end"]) for r in rows)
    log.info(f"[{g._rid}] access_status subject_type={subject_type} can_enter={can_enter}")
    return jsonify({"subject_type": subject_type, "subject_id": subject_id, "can_enter": can_enter})

# ───────────────────────── admin manual/cash periods ───────────────
@app.post("/api/admin/periods")
@auth_required
@admin_required
def admin_add_period():
    body = request.get_json(force=True, silent=True) or {}
    rid = getattr(g, "_rid", "-")
    log.info(f"[{rid}] /api/admin/periods start body={json.dumps(body, default=str)[:1000]}")

    user_membership_id = body.get("user_membership_id")
    owner_user_id = (body.get("owner_user_id") or g.user_id)
    subject_type = (body.get("subject_type") or "user").lower()
    subject_id = body.get("subject_id")
    plan_id = (body.get("plan_id") or "").strip()
    period_start_iso = body.get("period_start")
    period_end_iso = body.get("period_end")
    amount_cents = body.get("amount_cents")
    notes = body.get("notes")

    # ---- Validation
    if not plan_id or not period_start_iso or not period_end_iso:
        return err("period_start, period_end, plan_id required", 400)
    if subject_type not in ("user", "dependent"):
        return err("subject_type must be 'user' or 'dependent'", 400)
    if subject_type == "dependent" and not subject_id:
        return err("subject_id required for dependent", 400)

    # Parse ISO times
    try:
        ps = _parse_ts(period_start_iso)
        pe = _parse_ts(period_end_iso)
        log.info(f"[{rid}] parsed times ps={ps.isoformat()} pe={pe.isoformat()}")
    except Exception as e:
        log.warning(f"[{rid}] time parse failed: {e}")
        return err("Invalid datetime format; pass ISO 8601 strings", 400)
    if ps >= pe:
        return err("period_start must be before period_end", 400)

    # Plan exists?
    try:
        plan_rows = (
            sb_admin.table("membership_plans")
            .select("id")
            .eq("id", plan_id)
            .limit(1)
            .execute()
            .data
        )
        if not plan_rows:
            return err("plan not found", 400)
        log.info(f"[{rid}] plan ok id={plan_id}")
    except Exception as e:
        return err(f"plan lookup failed: {e}", 400)

    # amount
    try:
        if amount_cents is not None:
            amount_cents = int(amount_cents)
            if amount_cents < 0:
                return err("amount_cents must be >= 0", 400)
    except Exception:
        return err("amount_cents must be an integer number of cents", 400)

    # ---- Ensure membership
    try:
        mem = None
        if user_membership_id:
            rows = (
                sb_admin.table("user_memberships")
                .select("*")
                .eq("id", user_membership_id)
                .limit(1)
                .execute()
                .data
            )
            if rows:
                mem = rows[0]
                log.info(f"[{rid}] using existing membership id={mem['id']}")
        if not mem:
            mem = ensure_membership(
                owner_user_id=owner_user_id,
                plan_id=plan_id,
                subject_user_id=(owner_user_id if subject_type == "user" else None),
                dependent_id=(subject_id if subject_type == "dependent" else None),
                status="active",
            )
            log.info(f"[{rid}] ensured membership id={mem['id']} owner={mem['owner_user_id']}")
    except Exception as e:
        return err(f"ensure_membership failed: {e}", 400)

    # ---- Idempotency: same window already present?
    try:
        existing = (
            sb_admin.table("membership_periods")
            .select("id")
            .eq("user_membership_id", mem["id"])
            .eq("period_start", ps.isoformat())
            .eq("period_end", pe.isoformat())
            .eq("is_voided", False)
            .limit(1)
            .execute()
            .data
        )
        if existing:
            pid = existing[0]["id"]
            log.info(f"[{rid}] idempotent: period already exists id={pid}")
            resp = jsonify({"ok": True, "idempotent": True, "membership_period_id": pid})
            resp.headers["x-request-id"] = rid
            return resp
    except Exception as e:
        log.warning(f"[{rid}] idempotency check failed (continuing): {e}")

    # ---- Insert coverage window
    try:
        mp = {
            "user_membership_id": mem["id"],
            "owner_user_id": mem["owner_user_id"],
            "subject_user_id": mem.get("subject_user_id"),
            "dependent_id": mem.get("dependent_id"),
            "plan_id": mem["plan_id"],
            "source": "manual",
            "source_ref": None,
            "period_start": ps.isoformat(),
            "period_end": pe.isoformat(),
        }
        ins = sb_admin.table("membership_periods").insert(mp).execute().data[0]
        log.info(f"[{rid}] inserted period id={ins['id']} {ps.isoformat()}..{pe.isoformat()}")
    except Exception as e:
        return err(f"period insert failed: {e}", 400)

    # ---- Optional receipt: non-fatal
    warnings: list[str] = []
    try:
        if amount_cents and amount_cents > 0:
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
                "amount_cents": amount_cents,
                "currency": "USD",
                "notes": (notes or "")[:500],
                "paid_at": datetime.now(timezone.utc),
                "created_by_user_id": g.user_id,
            }
            rec = sb_admin.table("payment_receipts").insert(receipt).execute().data[0]
            log.info(f"[{rid}] recorded cash receipt id={rec['id']} amount_cents={amount_cents}")
    except Exception as e:
        msg = f"receipt insert failed: {e}"
        log.warning(f"[{rid}] {msg}")
        warnings.append(msg)

    # ---- Keep membership marked active (best effort)
    try:
        sb_admin.table("user_memberships").update({"status": "active"}).eq("id", mem["id"]).execute()
    except Exception as e:
        log.warning(f"[{rid}] set membership active failed: {e}")

    out = {"ok": True, "membership_period_id": ins["id"]}
    if warnings:
        out["warnings"] = warnings
    resp = jsonify(out)
    resp.headers["x-request-id"] = rid
    return resp

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

# ───────────────────── admin: link Stripe customer ─────────────────
def _map_subscription_status(status: str) -> str:
    status = (status or "").lower()
    if status in ("active", "trialing"):
        return "active"
    if status in ("past_due", "incomplete", "unpaid", "paused"):
        return "past_due"
    if status in ("canceled", "incomplete_expired"):
        return "canceled"
    return "past_due"  # safer than "inactive" unless you KNOW it's in your enum

def _stripe_list_data(obj) -> list:
    if obj is None:
        return []
    if hasattr(obj, "data"):
        return getattr(obj, "data") or []
    try:
        return obj.get("data") or []
    except Exception:
        return []

def sync_stripe_for_user(user_id: str, *, min_age_seconds: int = 300, force: bool = False) -> dict:
    """
    Sync Stripe subscriptions -> local DB.
    NO DB schema changes.
    Throttle is in-memory only (per backend instance).
    """
    rid = getattr(g, "_rid", uuid4().hex[:8])

    if not STRIPE_SECRET_KEY:
        return {"ok": False, "error": "stripe not configured"}

    # Load Stripe customer id from existing profile column
    prof_rows = (
        sb_admin.table("user_profiles")
        .select("user_id,stripe_customer_id")
        .eq("user_id", user_id)
        .limit(1)
        .execute()
        .data
    )
    if not prof_rows:
        return {"ok": False, "error": "profile missing"}

    customer_id = prof_rows[0].get("stripe_customer_id")
    if not customer_id:
        return {"ok": True, "skipped": True, "reason": "no stripe_customer_id"}

    # Throttle (memory only)
    now = time.time()
    if not force and min_age_seconds:
        last = _STRIPE_SYNC_LAST.get(user_id, 0.0)
        if (now - last) < float(min_age_seconds):
            return {"ok": True, "skipped": True, "reason": "throttled"}

    lock = _get_user_lock(user_id)
    with lock:
        # re-check throttle inside lock
        now = time.time()
        if not force and min_age_seconds:
            last = _STRIPE_SYNC_LAST.get(user_id, 0.0)
            if (now - last) < float(min_age_seconds):
                return {"ok": True, "skipped": True, "reason": "throttled"}

        updated_memberships = 0
        created_periods = 0
        notes: list[str] = []

        # List subscriptions (all statuses)
        subs = stripe.Subscription.list(
            customer=customer_id,
            status="all",
            limit=100,
            expand=["data.items.data.price"],
        )

        for s in _stripe_list_data(subs):
            # dict vs object
            if isinstance(s, dict):
                sub_id = s.get("id")
                sub_status = s.get("status") or ""
                start_ts = s.get("current_period_start")
                end_ts = s.get("current_period_end")
                items = (s.get("items") or {}).get("data") or []
            else:
                sub_id = getattr(s, "id", None)
                sub_status = getattr(s, "status", "") or ""
                start_ts = getattr(s, "current_period_start", None)
                end_ts = getattr(s, "current_period_end", None)
                items = getattr(getattr(s, "items", None), "data", []) or []

            mapped_status = _map_subscription_status(sub_status)

            for it in items:
                price = it.get("price") if isinstance(it, dict) else getattr(it, "price", None)
                price_id = price.get("id") if isinstance(price, dict) else getattr(price, "id", None)
                if not price_id:
                    continue

                plan = _find_plan_by_price_id(price_id)
                if not plan:
                    notes.append(f"no plan for price_id={price_id}")
                    continue

                mem = ensure_membership(
                    owner_user_id=user_id,
                    plan_id=plan["id"],
                    subject_user_id=user_id,
                    dependent_id=None,
                    provider_customer_id=customer_id,
                    provider_subscription_id=sub_id,
                    status=mapped_status,
                )
                updated_memberships += 1

                # Ensure current period exists (idempotent check in code)
                if start_ts and end_ts:
                    src_ref = f"{sub_id}:{int(start_ts)}"
                    exists = (
                        sb_admin.table("membership_periods")
                        .select("id")
                        .eq("source", "stripe")
                        .eq("source_ref", src_ref)
                        .limit(1)
                        .execute()
                        .data
                    )
                    if not exists:
                        try:
                            sb_admin.table("membership_periods").insert(
                                {
                                    "user_membership_id": mem["id"],
                                    "owner_user_id": mem["owner_user_id"],
                                    "subject_user_id": mem.get("subject_user_id"),
                                    "dependent_id": mem.get("dependent_id"),
                                    "plan_id": mem["plan_id"],
                                    "source": "stripe",
                                    "source_ref": src_ref,
                                    "period_start": to_utc_ts(int(start_ts)),
                                    "period_end": to_utc_ts(int(end_ts)),
                                }
                            ).execute()
                            created_periods += 1
                        except Exception as e:
                            # In case of rare race duplicates, don’t fail check-in
                            notes.append(f"period insert failed (maybe duplicate): {str(e)[:120]}")

        _STRIPE_SYNC_LAST[user_id] = time.time()

        return {
            "ok": True,
            "customer_id": customer_id,
            "customer_url": stripe_customer_dashboard_url(customer_id),
            "updated_memberships": updated_memberships,
            "created_periods": created_periods,
            "notes": notes[:10],
        }
CRON_SECRET = os.getenv("CRON_SECRET")

@app.post("/internal/cron/stripe-reconcile")
def cron_stripe_reconcile():
    if not CRON_SECRET:
        return err("CRON_SECRET not configured", 500)

    if request.headers.get("x-cron-secret") != CRON_SECRET:
        return err("forbidden", 403)

    max_users = min(max(int(request.args.get("max_users", "5000")), 1), 50000)

    processed = 0
    synced = 0
    skipped = 0
    failed = 0

    # For most gyms, fetching all is fine. If you have tons of users, paginate.
    rows = (
        sb_admin.table("user_profiles")
        .select("user_id,stripe_customer_id")
        .execute()
        .data
    ) or []

    for r in rows:
        if processed >= max_users:
            break
        processed += 1

        uid = r.get("user_id")
        cid = r.get("stripe_customer_id")
        if not uid or not cid:
            skipped += 1
            continue

        try:
            # force=True disables throttle so cron always reconciles
            res = sync_stripe_for_user(uid, min_age_seconds=0, force=True)
            if res.get("skipped"):
                skipped += 1
            else:
                synced += 1
        except Exception as e:
            failed += 1
            log.warning(f"[cron] reconcile failed user_id={uid}: {str(e)[:200]}")

    return jsonify({"ok": True, "processed": processed, "synced": synced, "skipped": skipped, "failed": failed})

def _find_plan_by_price_id(price_id: str) -> dict | None:
    try:
        rows = (
            sb_admin.table("membership_plans")
            .select("id,slug,name,price_cents,currency,interval,interval_count")
            .eq("stripe_price_id", price_id)
            .limit(1)
            .execute()
            .data
        )
        return rows[0] if rows else None
    except Exception:
        return None

@app.post("/api/admin/stripe/link-customer")
@auth_required
@admin_required
def admin_link_stripe_customer():
    if not STRIPE_SECRET_KEY:
        return err("stripe not configured", 500)

    rid = getattr(g, "_rid", "-")
    body = request.get_json(force=True, silent=True) or {}
    user_id = (body.get("user_id") or "").strip()
    stripe_customer_id = (body.get("stripe_customer_id") or "").strip()
    email = (body.get("email") or "").strip()

    if not user_id:
        return err("user_id required", 400)

    linked: list[dict] = []
    warnings: list[str] = []

    # ---- Phase 1: resolve + persist the Stripe customer link (this is the core action)
    try:
        if not stripe_customer_id:
            if not email:
                prof = (
                    sb_admin.table("user_profiles")
                    .select("email")
                    .eq("user_id", user_id)
                    .limit(1)
                    .execute()
                    .data
                )
                if not prof or not prof[0].get("email"):
                    return err("Provide stripe_customer_id or a valid email to search Stripe.", 400)
                email = prof[0]["email"]

            custs = stripe.Customer.list(email=email, limit=10)
            if not custs or not custs.get("data"):
                return err(f"No Stripe customer found for email {email}", 404)
            stripe_customer_id = custs["data"][0]["id"]

        # persist on profile FIRST
        sb_admin.table("user_profiles").update(
            {"stripe_customer_id": stripe_customer_id}
        ).eq("user_id", user_id).execute()

    except Exception as e:
        log.error(f"[{rid}] link-customer resolve/persist failed: {e}")
        return err(f"link failed: {e}", 500)

    # ---- Phase 2: backfill (best effort — never fail request after link succeeded)
    try:
        subs = stripe.Subscription.list(
            customer=stripe_customer_id,
            status="all",
            limit=100,
            expand=["data.items.data.price"],
        )
    except Exception as e:
        warnings.append(f"Could not list subscriptions: {str(e)[:200]}")
        return jsonify({"ok": True, "customer_id": stripe_customer_id, "linked": [], "warnings": warnings})

    for s in subs.get("data", []) or []:
        sub_id = s.get("id")
        sub_status = s.get("status") or ""

        # IMPORTANT: membership_status enum safety
        mapped_status = _map_subscription_status(sub_status)

        items = (s.get("items") or {}).get("data") or []
        for it in items:
            price = it.get("price") or {}
            price_id = price.get("id")
            if not price_id:
                continue

            try:
                plan = _find_plan_by_price_id(price_id)
                if not plan:
                    linked.append(
                        {
                            "subscription_id": sub_id,
                            "status": sub_status,
                            "price_id": price_id,
                            "plan_id": None,
                            "plan_slug": None,
                            "period_backfilled": False,
                            "note": "No plan with matching stripe_price_id",
                        }
                    )
                    continue

                mem = ensure_membership(
                    owner_user_id=user_id,
                    plan_id=plan["id"],
                    subject_user_id=user_id,
                    dependent_id=None,
                    provider_customer_id=stripe_customer_id,
                    provider_subscription_id=sub_id,
                    status=mapped_status,
                )

                # backfill current period (idempotent)
                created_period = False
                start_ts = s.get("current_period_start")
                end_ts = s.get("current_period_end")
                if start_ts and end_ts:
                    src_ref = f"{sub_id}:{start_ts}"
                    period_start_dt = to_utc_ts(int(start_ts))
                    period_end_dt = to_utc_ts(int(end_ts))

                    existing = (
                        sb_admin.table("membership_periods")
                        .select("id")
                        .eq("user_membership_id", mem["id"])
                        .eq("source", "stripe")  # ✅ matches your CHECK constraint
                        .eq("source_ref", src_ref)
                        .limit(1)
                        .execute()
                        .data
                    )
                    if not existing:
                        # prevent dup by window too
                        existing = (
                            sb_admin.table("membership_periods")
                            .select("id")
                            .eq("user_membership_id", mem["id"])
                            .eq("period_start", period_start_dt)
                            .eq("period_end", period_end_dt)
                            .limit(1)
                            .execute()
                            .data
                        )

                    if not existing:
                        sb_admin.table("membership_periods").insert(
                            {
                                "user_membership_id": mem["id"],
                                "owner_user_id": mem["owner_user_id"],  # NOT NULL ✅
                                "subject_user_id": mem.get("subject_user_id"),
                                "dependent_id": mem.get("dependent_id"),
                                "plan_id": mem["plan_id"],  # NOT NULL ✅
                                "source": "stripe",  # ✅ allowed by CHECK constraint
                                "source_ref": src_ref,
                                "period_start": period_start_dt,
                                "period_end": period_end_dt,
                            }
                        ).execute()
                        created_period = True

                linked.append(
                    {
                        "subscription_id": sub_id,
                        "status": sub_status,
                        "price_id": price_id,
                        "plan_id": plan["id"],
                        "plan_slug": plan.get("slug"),
                        "period_backfilled": created_period,
                    }
                )

            except Exception as e:
                # don’t break the whole request — record the failure
                linked.append(
                    {
                        "subscription_id": sub_id,
                        "status": sub_status,
                        "price_id": price_id,
                        "plan_id": None,
                        "plan_slug": None,
                        "period_backfilled": False,
                        "note": f"Backfill error: {str(e)[:200]}",
                    }
                )
                continue

    return jsonify({"ok": True, "customer_id": stripe_customer_id, "linked": linked, "warnings": warnings})



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
          "waiver_required": bool,
          "waiver_signed": bool | null,
          "memberships": [{ "id": "...", "status": "...", "plan": {...} | null }]
        }],
        "count": <int>
      }
    """
    rid = getattr(g, "_rid", "-")
    now = datetime.now(timezone.utc)

    try:
        # 1) Users (owners)
        users: List[dict] = (
            sb_admin.table("user_profiles")
            .select("user_id,email,first_name,last_name,stripe_customer_id")
            .order("first_name", desc=False)
            .execute()
            .data
        )
        owner_ids = [u["user_id"] for u in users if u.get("user_id")]
        log.info(f"[{rid}] admin/overview users={len(users)}")

        # 2) Memberships (owned by these users)  ← owner-centric
        memberships: List[dict] = []
        if owner_ids:
            memberships = (
                sb_admin.table("user_memberships")
                .select("id,owner_user_id,subject_user_id,dependent_id,plan_id,status")
                .in_("owner_user_id", owner_ids)
                .execute()
                .data
            )
        log.info(f"[{rid}] admin/overview memberships={len(memberships)}")

        # 3) Plans referenced by those memberships
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

        # 4) Coverage windows for access ← compute by owner_user_id
        periods_by_owner: Dict[str, List[dict]] = {oid: [] for oid in owner_ids}
        if owner_ids:
            per_owner = (
                sb_admin.table("membership_periods")
                .select("owner_user_id,period_start,period_end,is_voided")
                .in_("owner_user_id", owner_ids)
                .eq("is_voided", False)
                .execute()
                .data
            )
            for r in per_owner:
                oid = r["owner_user_id"]
                periods_by_owner.setdefault(oid, []).append(r)

        def active_now(periods: List[dict]) -> bool:
            for pr in periods or []:
                try:
                    ps = _parse_ts(pr["period_start"])
                    pe = _parse_ts(pr["period_end"])
                    if ps <= now < pe:
                        return True
                except Exception:
                    continue
            return False

        # 5) Latest check-in per (user as subject) — unchanged
        last_checkin_by_subject: Dict[str, str] = {}
        if owner_ids:
            ch = (
                sb_admin.table("gym_checkins")
                .select("subject_user_id,scanned_at")
                .in_("subject_user_id", owner_ids)
                .order("scanned_at", desc=True)
                .execute()
                .data
            )
            for row in ch:
                sid = row.get("subject_user_id")
                if sid and sid not in last_checkin_by_subject:
                    last_checkin_by_subject[sid] = row["scanned_at"]

        # 6) Waiver requirement + signatures for these users (as subjects)
        active_w = (
            sb_admin.table("waivers")
            .select("id,version")
            .eq("is_active", True)
            .eq("required_for_purchase", True)
            .limit(1)
            .execute()
            .data
        )
        waiver_required = bool(active_w)
        waiver_id = active_w[0]["id"] if waiver_required else None
        waiver_version = active_w[0]["version"] if waiver_required else None

        signed_subjects: set[str] = set()
        if waiver_required and owner_ids:
            sig_rows = (
                sb_admin.table("waiver_signatures")
                .select("subject_user_id")
                .eq("waiver_id", waiver_id)
                .eq("waiver_version", waiver_version)
                .is_("revoked_at", "null")
                .in_("subject_user_id", owner_ids)
                .execute()
                .data
            )
            for s in sig_rows:
                sid = s.get("subject_user_id")
                if sid:
                    signed_subjects.add(sid)

        # 7) Shape response by owner
        mems_by_owner: Dict[str, List[dict]] = {}
        for m in memberships:
            oid = m["owner_user_id"]
            mems_by_owner.setdefault(oid, []).append(m)

        out_rows = []
        for u in users:
            oid = u["user_id"]
            u_mems = mems_by_owner.get(oid, [])
            mems_fmt = []
            for m in u_mems:
                plan = plans_by_id.get(m.get("plan_id"))
                mems_fmt.append({"id": m["id"], "status": m.get("status"), "plan": plan or None})

            out_rows.append(
                {
                    "user_id": oid,
                    "email": u.get("email"),
                    "first_name": u.get("first_name"),
                    "last_name": u.get("last_name"),
                    "last_checkin_at": last_checkin_by_subject.get(oid),
                    "has_access_now": active_now(periods_by_owner.get(oid, [])),
                    "waiver_required": waiver_required,
                    "waiver_signed": (oid in signed_subjects) if waiver_required else None,
                    "memberships": mems_fmt,
                    "stripe_customer_id": u.get("stripe_customer_id"),
                    "stripe_customer_url": stripe_customer_dashboard_url(u.get("stripe_customer_id")),

                }
            )

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
      "items": [{ ... }],
      "count": <int>
    }
    """
    try:
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

# memberships owned by me (for me or my dependents)
@app.get("/api/memberships/mine/summary")
@auth_required
def my_membership_summary():
    mems = (
        sb_admin.table("user_memberships")
        .select("id,status,plan_id,subject_user_id,dependent_id")
        .eq("owner_user_id", g.user_id)
        .execute()
        .data
    )
    if not mems:
        return jsonify({"items": [], "counts_by_plan": [], "count": 0})

    plan_ids = {m["plan_id"] for m in mems if m.get("plan_id")}
    plans = sb_admin.table("membership_plans").select("id,name").in_("id", list(plan_ids)).execute().data
    plan_by_id = {p["id"]: p for p in plans}

    # fetch dependents for labels
    dep_ids = [m["dependent_id"] for m in mems if m.get("dependent_id")]
    dep_map = {}
    if dep_ids:
        deps = (
            sb_admin.table("dependents")
            .select("id,first_name,last_name")
            .in_("id", dep_ids)
            .execute()
            .data
        )
        dep_map = {d["id"]: f"{d.get('first_name','')} {d.get('last_name','')}".strip() for d in deps}

    # shape items (+ human label)
    items = []
    for m in mems:
        subj_type = "user" if m.get("subject_user_id") else "dependent"
        subj_label = "Me" if subj_type == "user" else dep_map.get(m.get("dependent_id")) or "Dependent"
        items.append(
            {
                "id": m["id"],
                "status": m.get("status"),
                "plan": {"id": m["plan_id"], "name": plan_by_id.get(m["plan_id"], {}).get("name")},
                "subject_type": subj_type,
                "subject_id": m.get("subject_user_id") or m.get("dependent_id"),
                "subject_label": subj_label,
            }
        )

    # simple counts of active memberships per plan
    counts_map = {}
    for it in items:
        if it["status"] in ("active", "trialing"):  # include trialing as active
            k = it["plan"]["id"]
            counts_map[k] = counts_map.get(k, 0) + 1
    counts_by_plan = [
        {"plan_id": pid, "plan_name": plan_by_id.get(pid, {}).get("name"), "count_active": n} for pid, n in counts_map.items()
    ]

    return jsonify({"items": items, "counts_by_plan": counts_by_plan, "count": len(items)})

@app.get("/api/family/dependents")
@auth_required
def list_my_dependents():
    # fetch dependents linked to current user through guardian_links
    links = (
        sb_admin.table("guardian_links")
        .select("dependent_id,relationship,is_primary")
        .eq("guardian_user_id", g.user_id)
        .execute()
        .data
    )
    dep_ids = [l["dependent_id"] for l in links]
    if not dep_ids:
        return jsonify({"items": [], "count": 0})

    deps = (
        sb_admin.table("dependents")
        .select("id,first_name,last_name,date_of_birth,email")
        .in_("id", dep_ids)
        .order("first_name", desc=False)
        .execute()
        .data
    )
    # Attach link info (optional)
    by_id = {d["id"]: d for d in deps}
    for l in links:
        d = by_id.get(l["dependent_id"])
        if d:
            d["relationship"] = l.get("relationship")
            d["is_primary"] = l.get("is_primary")
    items = list(by_id.values())
    return jsonify({"items": items, "count": len(items)})

# ───────────────────────── admin: recent check-ins feed ────────────
@app.get("/api/admin/checkins/recent")
@auth_required
@admin_required
def admin_recent_checkins():
    rid = getattr(g, "_rid", "-")
    try:
        limit = min(max(int(request.args.get("limit", "50")), 1), 200)
        since_min = int(request.args.get("since_min", "0"))

        q = (
            sb_admin.table("gym_checkins")
            .select("id,subject_user_id,dependent_id,scanned_at,method,location,source,meta")
            .order("scanned_at", desc=True)
            .limit(limit)
        )
        if since_min > 0:
            since_dt = datetime.now(timezone.utc) - timedelta(minutes=since_min)
            q = q.gte("scanned_at", since_dt.isoformat())

        rows = q.execute().data or []

        user_ids = sorted({r.get("subject_user_id") for r in rows if r.get("subject_user_id")})
        dep_ids  = sorted({r.get("dependent_id")    for r in rows if r.get("dependent_id")})

        # Prefetch profiles
        users_by_id = {}
        if user_ids:
            ups = (
                sb_admin.table("user_profiles")
                .select("user_id,first_name,last_name,email")
                .in_("user_id", user_ids)
                .execute()
                .data
            ) or []
            users_by_id = {u["user_id"]: u for u in ups}

        # Prefetch dependents
        deps_by_id = {}
        if dep_ids:
            dps = (
                sb_admin.table("dependents")
                .select("id,first_name,last_name,email")
                .in_("id", dep_ids)
                .execute()
                .data
            ) or []
            deps_by_id = {d["id"]: d for d in dps}

        # ✅ Batch access checks (1 query for users, 1 for dependents)
        now_iso = datetime.now(timezone.utc).isoformat()
        active_users = set()
        active_deps = set()

        if user_ids:
            pr = (
                sb_admin.table("membership_periods")
                .select("subject_user_id")
                .eq("is_voided", False)
                .in_("subject_user_id", user_ids)
                .lte("period_start", now_iso)
                .gt("period_end", now_iso)
                .execute()
                .data
            ) or []
            active_users = {r.get("subject_user_id") for r in pr if r.get("subject_user_id")}

        if dep_ids:
            pr = (
                sb_admin.table("membership_periods")
                .select("dependent_id")
                .eq("is_voided", False)
                .in_("dependent_id", dep_ids)
                .lte("period_start", now_iso)
                .gt("period_end", now_iso)
                .execute()
                .data
            ) or []
            active_deps = {r.get("dependent_id") for r in pr if r.get("dependent_id")}

        # Shape response
        items = []
        for r in rows:
            su = r.get("subject_user_id")
            di = r.get("dependent_id")

            if su:
                prof = users_by_id.get(su, {})
                label = (
                    f"{(prof.get('first_name') or '').strip()} {(prof.get('last_name') or '').strip()}".strip()
                    or prof.get("email")
                    or "Member"
                )
                items.append({
                    "id": r["id"],
                    "scanned_at": r.get("scanned_at"),
                    "method": r.get("method"),
                    "location": r.get("location"),
                    "source": r.get("source"),
                    "subject_type": "user",
                    "subject_id": su,
                    "subject_label": label,
                    "email": prof.get("email"),
                    "has_access_now": su in active_users,
                })
            else:
                dep = deps_by_id.get(di, {})
                label = (
                    f"{(dep.get('first_name') or '').strip()} {(dep.get('last_name') or '').strip()}".strip()
                    or "Dependent"
                )
                items.append({
                    "id": r["id"],
                    "scanned_at": r.get("scanned_at"),
                    "method": r.get("method"),
                    "location": r.get("location"),
                    "source": r.get("source"),
                    "subject_type": "dependent",
                    "subject_id": di,
                    "subject_label": label,
                    "email": dep.get("email"),
                    "has_access_now": di in active_deps,
                })

        return jsonify({"items": items, "count": len(items)})

    except Exception as e:
        # ✅ This will show you EXACTLY where Errno 11 is thrown
        log.error(f"[{rid}] admin_recent_checkins failed: {e}", exc_info=True)
        return err(f"failed to load recent check-ins: {e}", 500)

@app.get("/api/admin/mailchimp/health")
@auth_required
@admin_required
def mailchimp_health():
    if not _mailchimp_enabled():
        return err("mailchimp not configured", 500)
    return jsonify({
        "ok": True,
        "audience_id": MAILCHIMP_AUDIENCE_ID,
        "server_prefix": MAILCHIMP_SERVER_PREFIX,
        "from_name": MAILCHIMP_FROM_NAME,
        "reply_to": MAILCHIMP_REPLY_TO,
    })

@app.post("/api/admin/mailchimp/sync-users")
@auth_required
@admin_required
def mailchimp_sync_users():
    """
    Sync your Supabase users -> Mailchimp audience (adds/updates list members).
    Body:
      { "mode": "all" } OR { "mode": "selected", "user_ids": [...] }
    """
    try:
        _mc_require()
        body = request.get_json(force=True, silent=True) or {}
        mode = (body.get("mode") or "all").lower()
        user_ids = body.get("user_ids") or []

        q = sb_admin.table("user_profiles").select("user_id,email,first_name,last_name,phone,birthday")

        if mode == "selected":
            if not isinstance(user_ids, list) or not user_ids:
                return err("user_ids required for mode=selected", 400)
            q = q.in_("user_id", user_ids)

        rows = q.execute().data or []
        rows = [r for r in rows if (r.get("email") or "").strip()]

        synced = 0
        failed = 0
        failures: list[dict] = []

        for r in rows:
            em = (r.get("email") or "").strip()
            try:
                ph = str(r.get("phone")).strip() if r.get("phone") else None
                bday = str(r.get("birthday")).strip() if r.get("birthday") else None

                mc_upsert_member(
                    email=em,
                    first_name=(r.get("first_name") or "").strip() or None,
                    last_name=(r.get("last_name") or "").strip() or None,
                    phone=ph,
                    birthday=bday,
                )
                synced += 1
            except Exception as e:
                failed += 1
                failures.append({"email": em, "error": str(e)[:250]})
                log.warning(
                    f"[{getattr(g, '_rid', '-')}] mailchimp sync failed email={em}: {str(e)[:200]}"
                )

        out = {"ok": True, "mode": mode, "synced": synced, "failed": failed}
        if failures:
            out["failures"] = failures[:50]  # avoid huge payloads
        return jsonify(out)

    except Exception as e:
        return err(f"sync failed: {e}", 500)

@app.post("/api/admin/mailchimp/send")
@auth_required
@admin_required
def mailchimp_send():
    """
    Send a Mailchimp campaign.
    Body:
      {
        "mode": "all" | "selected",
        "user_ids": ["..."] (required if selected),
        "subject": "string",
        "message": "string",
        "from_name": "optional",
        "reply_to": "optional",
        "delete_segment_after": true|false (optional, default true)
      }
    """
    try:
        _mc_require()
        body = request.get_json(force=True, silent=True) or {}

        mode = (body.get("mode") or "all").lower()
        subject = (body.get("subject") or "").strip()
        message = (body.get("message") or "").strip()
        from_name = (body.get("from_name") or "").strip() or None
        reply_to = (body.get("reply_to") or "").strip() or None
        delete_segment_after = body.get("delete_segment_after", True)

        if mode not in ("all", "selected"):
            return err("mode must be 'all' or 'selected'", 400)
        if not subject:
            return err("subject required", 400)
        if not message:
            return err("message required", 400)

        segment_id = None
        recipient_count = 0
        failed_upserts: list[dict] = []

        if mode == "selected":
            user_ids = body.get("user_ids") or []
            if not isinstance(user_ids, list) or not user_ids:
                return err("user_ids required for mode=selected", 400)

            rows = (
                sb_admin.table("user_profiles")
                .select("user_id,email,first_name,last_name,phone,birthday")
                .in_("user_id", user_ids)
                .execute()
                .data
            ) or []

            emails: list[str] = []

            for r in rows:
                em = (r.get("email") or "").strip()
                if not em:
                    continue

                try:
                    ph = str(r.get("phone")).strip() if r.get("phone") else None
                    bday = str(r.get("birthday")).strip() if r.get("birthday") else None

                    mc_upsert_member(
                        email=em,
                        first_name=(r.get("first_name") or "").strip() or None,
                        last_name=(r.get("last_name") or "").strip() or None,
                        phone=ph,
                        birthday=bday,
                    )
                    emails.append(em)
                except Exception as e:
                    failed_upserts.append({"email": em, "error": str(e)[:250]})
                    continue

            emails = sorted(set(emails))
            if not emails:
                first = failed_upserts[0] if failed_upserts else None
                return err(f"no valid emails could be upserted. first_error={first}", 400)

            recipient_count = len(emails)
            seg_name = f"temp-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid4().hex[:6]}"
            segment_id = mc_create_static_segment(seg_name, emails)

        else:
            # mode == "all"
            recipient_count = -1

        # ✅ Create campaign (works for BOTH all + selected)
        camp = mc_create_campaign(subject, segment_id=segment_id, from_name=from_name, reply_to=reply_to)
        campaign_id = camp.get("id")
        if not campaign_id:
            raise ValueError("Mailchimp did not return campaign id")

        # ✅ Set content + send
        mc_set_campaign_content(campaign_id, subject, message)
        mc_send_campaign(campaign_id)

        # ✅ Cleanup temporary segment if used
        if segment_id is not None and delete_segment_after:
            mc_delete_segment(segment_id)

        resp = {
            "ok": True,
            "mode": mode,
            "campaign_id": campaign_id,
            "segment_id": segment_id,
            "recipient_count": recipient_count,
        }
        if failed_upserts:
            resp["failed_upserts"] = failed_upserts

        return jsonify(resp)

    except Exception as e:
        return err(f"send failed: {e}", 500)

# ───────────────────────── user: profile updates ──────────────────────
# ───────────────────────── user: profile updates ──────────────────────
@app.post("/api/user/update-phone")
@auth_required
def update_phone():
    rid = getattr(g, "_rid", "-")
    body = request.get_json(force=True, silent=True) or {}
    
    user_id = body.get('user_id')
    phone = body.get('phone')
    email = body.get('email')
    first_name = body.get('first_name', '')
    last_name = body.get('last_name', '')
    sms_consent = body.get('sms_consent', False) # ✅ Catch the consent from React

    if not user_id or not phone:
        return err("Missing user ID or phone number", 400)
        
    if user_id != g.user_id:
        return err("Forbidden: Cannot update another user's profile", 403)

    try:
        # 1. Save to Supabase WITH the timestamped audit trail
        update_data = {'phone': phone}
        if sms_consent:
            update_data['sms_consent'] = True
            update_data['sms_consent_at'] = datetime.now(timezone.utc).isoformat()

        sb_admin.table('user_profiles').update(update_data).eq('user_id', user_id).execute()

        # 2. Push to Mailchimp
        if email:
            mc_upsert_member(
                email=email,
                first_name=first_name,
                last_name=last_name,
                phone=phone
            )

        log.info(f"[{rid}] Phone & consent updated successfully for {user_id}")
        return jsonify({"status": "success", "phone": phone}), 200

    except Exception as e:
        log.error(f"[{rid}] Error updating phone: {e}")
        return err(f"Failed to update phone: {e}", 500)
# ───────────────────────── run server ──────────────────────────────
if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    log.info(f"Starting server on 0.0.0.0:{port}  FRONTEND_URL={FRONTEND_URL}")
    app.run(host="0.0.0.0", port=port, debug=True)
