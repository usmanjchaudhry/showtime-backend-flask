# app.py
import os
from datetime import datetime, timezone

from flask import Flask, jsonify, request, make_response, g
from dotenv import load_dotenv
from flask_cors import CORS
from functools import wraps

import stripe

from supabase import create_client, Client
from supabase.lib.client_options import ClientOptions

# ────────────────────────── env / clients ──────────────────────────
load_dotenv()

SUPABASE_URL = os.environ["SUPABASE_URL"]
SERVICE_KEY = os.environ["SUPABASE_SERVICE_ROLE"]
ANON_KEY = os.getenv("SUPABASE_ANON")

STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")

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

# ────────────────────────── flask + cors ───────────────────────────
app = Flask(__name__)
CORS_ORIGINS = ["http://localhost:3000", "http://localhost:5173"]
CORS(
    app,
    resources={
        r"/(signup|login|api/.*|ping)": {"origins": CORS_ORIGINS}
    },
)

def err(msg, code=400):
    return make_response({"error": str(msg)}, code)

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
        except Exception as e:
            return err(f"profile lookup failed: {e}", 500)
        if not is_admin:
            return err("forbidden", 403)
        return fn(*args, **kwargs)
    return wrapper

# ────────────────────────── small utils ────────────────────────────
def to_utc_ts(sec: int) -> datetime:
    return datetime.fromtimestamp(sec, tz=timezone.utc)

def get_or_create_stripe_customer(user_id: str) -> str:
    """Return stripe_customer_id for a user, creating if missing."""
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

    # Create a Stripe customer
    full_name = " ".join([prof.get("first_name") or "", prof.get("last_name") or ""]).strip() or None
    customer = stripe.Customer.create(
        email=prof.get("email"),
        name=full_name,
        metadata={"user_id": user_id},
    )
    cid = customer.id
    # persist
    sb_admin.table("user_profiles").update({"stripe_customer_id": cid}).eq("user_id", user_id).execute()
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
    """Find or create a user_memberships row for this Stripe subscription."""
    # try lookup by provider_subscription_id first
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
        # or by (owner, subject/dependent, plan) where status not canceled
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
        # update provider ids if we learned them
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
        return mem

    # create brand new membership
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
    return mem

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
    return jsonify(rows[0])

@app.get("/api/plans")
def list_plans():
    rows = (
        sb_admin.table("membership_plans")
        .select("id,name,description,price_cents,currency,interval,interval_count,stripe_price_id")
        .eq("is_active", True)
        .order("created_at")
        .execute()
        .data
    )
    return jsonify(rows)

# ───────────────────────── waiver endpoints ────────────────────────
@app.get("/api/waivers/active")
@auth_required
def waiver_active():
    """Return the active waiver and whether the given subject has signed it."""
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
        .limit(1)
        .execute()
        .data
    )
    if not waivers:
        return jsonify({"waiver": None, "signed": False})

    w = waivers[0]
    # signed?
    q = sb_admin.table("waiver_signatures").select("id").eq("waiver_id", w["id"]).eq("waiver_version", w["version"])
    if subject_type == "user":
        q = q.eq("subject_user_id", subject_id).is_("revoked_at", "null")
    else:
        q = q.eq("dependent_id", subject_id).is_("revoked_at", "null")
    signed = bool(q.limit(1).execute().data)

    return jsonify({"waiver": w, "signed": signed})

@app.post("/api/waivers/sign")
@auth_required
def waiver_sign():
    """Sign the current active waiver for the subject (user or dependent)."""
    body = request.get_json(force=True, silent=True) or {}
    subject_type = (body.get("subject_type") or "user").lower()
    subject_id = body.get("subject_id")
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
        .limit(1)
        .execute()
        .data
    )
    if not waivers:
        return err("no active waiver to sign", 400)
    w = waivers[0]

    payload = {
        "waiver_id": w["id"],
        "waiver_version": w["version"],
        "signed_by_user_id": g.user_id,
        "relationship_to_subject": body.get("relationship_to_subject"),
        "full_name": body.get("full_name"),
        "date_of_birth": body.get("date_of_birth"),
        "signature_svg": body.get("signature_svg"),
        "signature_image_url": body.get("signature_image_url"),
        "pdf_url": body.get("pdf_url"),
        "ip_address": request.remote_addr,
        "user_agent": request.headers.get("User-Agent"),
    }
    if subject_type == "user":
        payload["subject_user_id"] = subject_id
    else:
        payload["dependent_id"] = subject_id

    try:
        sig = sb_admin.table("waiver_signatures").insert(payload).execute().data[0]
    except Exception as e:
        return err(f"sign failed: {e}", 400)

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
    """
    Body:
      {
        "plan_id": "...",
        "subject_type": "user" | "dependent",
        "subject_id": "<dependent uuid if subject_type=dependent>"
      }
    """
    if not STRIPE_SECRET_KEY:
        return err("stripe not configured", 500)

    body = request.get_json(force=True, silent=True) or {}
    plan_id = body.get("plan_id")
    subject_type = (body.get("subject_type") or "user").lower()
    subject_id = body.get("subject_id")

    if not plan_id:
        return err("plan_id required", 400)
    if subject_type not in ("user", "dependent"):
        return err("subject_type must be 'user' or 'dependent'", 400)
    if subject_type == "dependent" and not subject_id:
        return err("subject_id required for dependent", 400)

    # fetch plan
    plans = (
        sb_admin.table("membership_plans")
        .select("*")
        .eq("id", plan_id)
        .eq("is_active", True)
        .limit(1)
        .execute()
        .data
    )
    if not plans:
        return err("plan not found or inactive", 404)
    plan = plans[0]
    price_id = plan.get("stripe_price_id")
    if not price_id:
        return err("plan missing stripe_price_id", 400)

    # ensure Stripe customer on the payer (owner)
    customer_id = get_or_create_stripe_customer(g.user_id)

    # build metadata used in webhooks
    md = {
        "owner_user_id": g.user_id,
        "plan_id": plan_id,
        "subject_user_id": g.user_id if subject_type == "user" else "",
        "dependent_id": subject_id if subject_type == "dependent" else "",
    }

    try:
        sess = stripe.checkout.Session.create(
            mode="subscription",
            line_items=[{"price": price_id, "quantity": 1}],
            customer=customer_id,
            success_url=f"{FRONTEND_URL}/billing/success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{FRONTEND_URL}/billing/cancel",
            metadata=md,
            subscription_data={"metadata": md},
        )
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

    # 1) Checkout completed -> ensure user_membership exists
    if etype == "checkout.session.completed":
        sess = event["data"]["object"]
        sub_id = sess.get("subscription")
        customer_id = sess.get("customer")
        md = sess.get("metadata", {}) or {}
        plan_id = md.get("plan_id")
        owner_user_id = md.get("owner_user_id")
        subject_user_id = md.get("subject_user_id") or None
        dependent_id = md.get("dependent_id") or None

        if not (plan_id and owner_user_id and sub_id and customer_id):
            # nothing we can safely create
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

    # 2) Invoice paid -> write coverage + receipt
    if etype == "invoice.paid":
        inv = event["data"]["object"]
        sub_id = inv.get("subscription")
        customer_id = inv.get("customer")
        invoice_id = inv.get("id")
        amount_paid = inv.get("amount_paid") or 0
        currency = (inv.get("currency") or "usd").upper()

        # find membership by subscription id
        mem_rows = (
            sb_admin.table("user_memberships")
            .select("*")
            .eq("provider_subscription_id", sub_id)
            .limit(1)
            .execute()
            .data
        )
        if not mem_rows:
            # nothing to attach; ignore politely
            return jsonify({"ok": True})
        mem = mem_rows[0]

        # read first invoice line period
        lines = inv.get("lines", {}).get("data", [])
        if not lines:
            return jsonify({"ok": True})
        period = lines[0].get("period", {})
        start_ts = period.get("start")
        end_ts = period.get("end")
        if not (start_ts and end_ts):
            return jsonify({"ok": True})

        # Avoid duplicate coverage per invoice
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
            # create coverage window
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

        # record a receipt (idempotent-ish)
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

        # keep membership active
        sb_admin.table("user_memberships").update({"status": "active"}).eq("id", mem["id"]).execute()
        return jsonify({"ok": True})

    # 3) Payment failed -> mark past_due
    if etype in ("invoice.payment_failed",):
        inv = event["data"]["object"]
        sub_id = inv.get("subscription")
        sb_admin.table("user_memberships").update({"status": "past_due"}).eq("provider_subscription_id", sub_id).execute()
        return jsonify({"ok": True})

    # 4) Subscription canceled -> mark canceled
    if etype in ("customer.subscription.deleted",):
        sub = event["data"]["object"]
        sub_id = sub.get("id")
        ends_at = sub.get("current_period_end")
        patch = {"status": "canceled"}
        if ends_at:
            patch["current_period_end"] = to_utc_ts(ends_at)
        sb_admin.table("user_memberships").update(patch).eq("provider_subscription_id", sub_id).execute()
        return jsonify({"ok": True})

    # default
    return jsonify({"ok": True})

# ───────────────────────── access check ────────────────────────────
@app.get("/api/access/status")
@auth_required
def access_status():
    """
    Query params:
      subjectType=user|dependent  (default: user)
      subjectId=<uuid>           (required if subjectType=dependent)
    """
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
    return jsonify({"subject_type": subject_type, "subject_id": subject_id, "can_enter": can_enter})

# ───────────────────────── manual/cash admin ───────────────────────
@app.post("/api/admin/periods")
@auth_required
@admin_required
def admin_add_period():
    """
    Body:
      {
        "user_membership_id": "...",  (or provide owner_user_id + subject info + plan_id)
        "owner_user_id": "...",
        "subject_type": "user"|"dependent",
        "subject_id": "...",          (if dependent)
        "plan_id": "...",
        "period_start": "2025-08-01T00:00:00Z",
        "period_end":   "2025-09-01T00:00:00Z",
        "amount_cents": 5000,
        "notes": "Paid cash at front desk"
      }
    """
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
        # create/find membership container (manual)
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

    # keep membership active
    sb_admin.table("user_memberships").update({"status": "active"}).eq("id", mem["id"]).execute()
    return jsonify({"ok": True})

# ───────────────────────── list profiles (dev) ─────────────────────
@app.get("/api/profiles")
def list_profiles():
    rows = sb_admin.table("user_profiles").select("*").execute().data
    return jsonify(rows)

# ───────────────────────── run dev server ──────────────────────────
if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    app.run(host="0.0.0.0", port=port, debug=True)
