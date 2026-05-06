# core.py
import os
import logging
from datetime import datetime, timezone, timedelta
import calendar
from functools import wraps
from flask import request, make_response, g
from dotenv import load_dotenv
import stripe
from supabase import create_client, Client
from supabase.lib.client_options import SyncClientOptions as ClientOptions

load_dotenv()

# ────────────────────────── env / clients ──────────────────────────
SUPABASE_URL = os.environ["SUPABASE_URL"]
SERVICE_KEY = os.environ["SUPABASE_SERVICE_ROLE"]
ANON_KEY = os.getenv("SUPABASE_ANON")

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173").rstrip("/")
WAIVER_BUCKET = os.getenv("WAIVER_BUCKET", "waivers")
CHECKIN_QR_SECRET = os.getenv("CHECKIN_QR_SECRET", "dev-qr-secret")

stripe.api_key = STRIPE_SECRET_KEY

sb_admin: Client = create_client(
    SUPABASE_URL, SERVICE_KEY, options=ClientOptions(auto_refresh_token=False, persist_session=False)
)
sb_public: Client = create_client(
    SUPABASE_URL, ANON_KEY or SERVICE_KEY, options=ClientOptions(auto_refresh_token=False, persist_session=False)
)

# ────────────────────────── logging setup ──────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("api")

# ────────────────────────── shared utilities ───────────────────────
def err(msg, code=400):
    log.warning(f"ERR {code}: {msg}")
    return make_response({"error": str(msg)}, code)

def _parse_ts(s: str) -> datetime:
    if isinstance(s, datetime): return s
    return datetime.fromisoformat(str(s).replace("Z", "+00:00"))

def to_utc_ts(sec: int) -> datetime:
    return datetime.fromtimestamp(int(sec), tz=timezone.utc)

def add_interval(dt: datetime, interval: str, count: int) -> datetime:
    interval = (interval or "").lower()
    count = int(count or 1)
    if interval == "day": return dt + timedelta(days=count)
    if interval == "week": return dt + timedelta(weeks=count)
    if interval == "month":
        month0 = dt.month - 1 + count
        year = dt.year + month0 // 12
        month = month0 % 12 + 1
        day = min(dt.day, calendar.monthrange(year, month)[1])
        return dt.replace(year=year, month=month, day=day)
    if interval == "year":
        try: return dt.replace(year=dt.year + count)
        except ValueError: return dt.replace(month=2, day=28, year=dt.year + count)
    return dt + timedelta(days=count)

# ────────────────────────── auth decorators ──────────────────────────
def _bearer():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "): return auth[7:].strip()
    return None

def auth_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = _bearer()
        if not token: return err("missing bearer token", 401)
        try:
            res = sb_public.auth.get_user(token)
            if not res.user: return err("invalid token", 401)
            g.user_id = res.user.id
            g.user_email = res.user.email
        except Exception as e:
            return err(f"invalid token: {e}", 401)
        return fn(*args, **kwargs)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not getattr(g, "user_id", None): return err("unauthorized", 401)
        try:
            rows = sb_admin.table("user_profiles").select("is_admin").eq("user_id", g.user_id).limit(1).execute().data
            is_admin = bool(rows and rows[0].get("is_admin"))
        except Exception as e:
            return err(f"profile lookup failed: {e}", 500)
        if not is_admin: return err("forbidden", 403)
        return fn(*args, **kwargs)
    return wrapper

# ────────────────────────── shared db logic ──────────────────────────
def ensure_membership(owner_user_id: str, plan_id: str, *, subject_user_id: str | None = None, dependent_id: str | None = None, provider_customer_id: str | None = None, provider_subscription_id: str | None = None, status: str = "active"):
    mem = None
    if provider_subscription_id:
        rows = sb_admin.table("user_memberships").select("*").eq("provider_subscription_id", provider_subscription_id).limit(1).execute().data
        if rows: mem = rows[0]

    if not mem:
        q = sb_admin.table("user_memberships").select("*").eq("owner_user_id", owner_user_id).eq("plan_id", plan_id)
        if subject_user_id: q = q.eq("subject_user_id", subject_user_id).is_("dependent_id", "null")
        else: q = q.eq("dependent_id", dependent_id).is_("subject_user_id", "null")
        rows = q.limit(1).execute().data
        if rows: mem = rows[0]

    if mem:
        patch = {}
        if provider_customer_id and not mem.get("provider_customer_id"): patch["provider_customer_id"] = provider_customer_id
        if provider_subscription_id and not mem.get("provider_subscription_id"): patch["provider_subscription_id"] = provider_subscription_id
        if status and mem.get("status") != status: patch["status"] = status
        if patch:
            mem = sb_admin.table("user_memberships").update(patch).eq("id", mem["id"]).execute().data[0]
            log.info(f"updated membership {mem['id']} with {patch}")
        return mem

    payload = {
        "owner_user_id": owner_user_id, "plan_id": plan_id, "status": status,
        "provider_customer_id": provider_customer_id, "provider_subscription_id": provider_subscription_id,
    }
    if subject_user_id: payload["subject_user_id"] = subject_user_id
    else: payload["dependent_id"] = dependent_id

    mem = sb_admin.table("user_memberships").insert(payload).execute().data[0]
    return mem

def has_access_now_for_subject(subject_user_id: str | None, dependent_id: str | None) -> bool:
    now = datetime.now(timezone.utc)
    q = sb_admin.table("membership_periods").select("period_start,period_end").eq("is_voided", False)
    if subject_user_id: q = q.eq("subject_user_id", subject_user_id)
    else: q = q.eq("dependent_id", dependent_id)
    rows = q.execute().data
    for r in rows:
        try:
            if _parse_ts(r["period_start"]) <= now < _parse_ts(r["period_end"]): return True
        except Exception: continue
    return False

def record_checkin(*, subject_type: str, subject_id: str, method: str = "qr", location: str | None = None, source: str | None = None, meta: dict | None = None) -> dict:
    row = {
        "subject_user_id": subject_id if subject_type == "user" else None,
        "dependent_id": subject_id if subject_type == "dependent" else None,
        "method": method or "qr", "location": location, "source": source, "meta": meta or {},
    }
    rec = sb_admin.table("gym_checkins").insert(row).execute().data[0]
    rec["has_access_now"] = has_access_now_for_subject(rec.get("subject_user_id"), rec.get("dependent_id"))
    return rec

def stripe_customer_dashboard_url(customer_id: str | None) -> str | None:
    if not customer_id:
        return None
    return f"https://dashboard.stripe.com/customers/{customer_id}"