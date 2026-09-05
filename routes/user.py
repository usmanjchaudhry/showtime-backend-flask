# routes/user.py
import os
import hmac
import hashlib
import base64
import time
import threading
from datetime import datetime, timezone, timedelta
from uuid import uuid4

import stripe
from flask import Blueprint, request, jsonify, g

# ✅ Import shared tools from core.py
from core import (
    sb_admin, err, log, auth_required, _parse_ts, to_utc_ts,
    has_access_now_for_subject, record_checkin, CHECKIN_QR_SECRET, 
    STRIPE_SECRET_KEY, ensure_membership
)

user_bp = Blueprint('user', __name__)

stripe.api_key = STRIPE_SECRET_KEY

# ───────────────────────── sync & helper tools ───────────────────────
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

def _map_subscription_status(status: str) -> str:
    status = (status or "").lower()
    if status in ("active", "trialing"): return "active"
    if status in ("past_due", "incomplete", "unpaid", "paused"): return "past_due"
    if status in ("canceled", "incomplete_expired"): return "canceled"
    return "past_due" 

def _find_plan_by_price_id(price_id: str) -> dict | None:
    try:
        rows = sb_admin.table("membership_plans").select("id,slug,name,price_cents,currency,interval,interval_count").eq("stripe_price_id", price_id).limit(1).execute().data
        return rows[0] if rows else None
    except Exception: return None

def stripe_customer_dashboard_url(customer_id: str | None) -> str | None:
    if not customer_id: return None
    return f"https://dashboard.stripe.com/customers/{customer_id}"

def sync_stripe_for_user(user_id: str, *, min_age_seconds: int = 300, force: bool = False) -> dict:
    rid = getattr(g, "_rid", uuid4().hex[:8])
    if not STRIPE_SECRET_KEY: return {"ok": False, "error": "stripe not configured"}

    prof_rows = sb_admin.table("user_profiles").select("user_id,stripe_customer_id").eq("user_id", user_id).limit(1).execute().data
    if not prof_rows: return {"ok": False, "error": "profile missing"}

    customer_id = prof_rows[0].get("stripe_customer_id")
    if not customer_id: return {"ok": True, "skipped": True, "reason": "no stripe_customer_id"}

    now = time.time()
    if not force and min_age_seconds:
        if (now - _STRIPE_SYNC_LAST.get(user_id, 0.0)) < float(min_age_seconds):
            return {"ok": True, "skipped": True, "reason": "throttled"}

    lock = _get_user_lock(user_id)
    with lock:
        now = time.time()
        if not force and min_age_seconds and (now - _STRIPE_SYNC_LAST.get(user_id, 0.0)) < float(min_age_seconds):
            return {"ok": True, "skipped": True, "reason": "throttled"}

        updated_memberships, created_periods, notes = 0, 0, []

        subs = stripe.Subscription.list(customer=customer_id, status="all", limit=100, expand=["data.items.data.price"])
        for s in subs.get("data", []) if isinstance(subs, dict) else getattr(subs, "data", []):
            sub_id = s.get("id") if isinstance(s, dict) else getattr(s, "id", None)
            sub_status = s.get("status", "") if isinstance(s, dict) else getattr(s, "status", "")
            start_ts = s.get("current_period_start") if isinstance(s, dict) else getattr(s, "current_period_start", None)
            end_ts = s.get("current_period_end") if isinstance(s, dict) else getattr(s, "current_period_end", None)
            items = (s.get("items", {}).get("data", []) if isinstance(s, dict) else getattr(getattr(s, "items", None), "data", []))

            mapped_status = _map_subscription_status(sub_status)

            for it in items:
                price = it.get("price") if isinstance(it, dict) else getattr(it, "price", None)
                price_id = price.get("id") if isinstance(price, dict) else getattr(price, "id", None)
                if not price_id: continue

                plan = _find_plan_by_price_id(price_id)
                if not plan:
                    notes.append(f"no plan for price_id={price_id}")
                    continue

                # 🛡️ THE CASH SHIELD: Prevent Stripe from downgrading an active cash user during QR Scan
                if mapped_status != "active":
                    try:
                        mem_check = sb_admin.table("user_memberships").select("payment_provider, current_period_end").eq("owner_user_id", user_id).eq("plan_id", plan["id"]).execute().data
                        if mem_check:
                            provider = mem_check[0].get("payment_provider")
                            pend = mem_check[0].get("current_period_end")
                            if provider == "cash" and pend:
                                pend_dt = datetime.fromisoformat(pend.replace("Z", "+00:00"))
                                if pend_dt > datetime.now(timezone.utc):
                                    mapped_status = "active" # Override Stripe
                                    notes.append("Shielded cash payment from Stripe downgrade")
                    except Exception as e:
                        log.warning(f"Cash shield error: {e}")

                mem = ensure_membership(
                    owner_user_id=user_id, plan_id=plan["id"], subject_user_id=user_id,
                    dependent_id=None, provider_customer_id=customer_id,
                    provider_subscription_id=sub_id, status=mapped_status
                )
                updated_memberships += 1

                if start_ts and end_ts:
                    src_ref = f"{sub_id}:{int(start_ts)}"
                    exists = sb_admin.table("membership_periods").select("id").eq("source", "stripe").eq("source_ref", src_ref).limit(1).execute().data
                    if not exists:
                        try:
                            sb_admin.table("membership_periods").insert({
                                "user_membership_id": mem["id"], "owner_user_id": mem["owner_user_id"],
                                "subject_user_id": mem.get("subject_user_id"), "dependent_id": mem.get("dependent_id"),
                                "plan_id": mem["plan_id"], "source": "stripe", "source_ref": src_ref,
                                "period_start": to_utc_ts(int(start_ts)).isoformat(),
                                "period_end": to_utc_ts(int(end_ts)).isoformat()
                            }).execute()
                            created_periods += 1
                        except Exception as e:
                            notes.append(f"period insert failed: {str(e)[:120]}")

        _STRIPE_SYNC_LAST[user_id] = time.time()
        return {
            "ok": True, "customer_id": customer_id, "customer_url": stripe_customer_dashboard_url(customer_id),
            "updated_memberships": updated_memberships, "created_periods": created_periods, "notes": notes[:10]
        }

# ───────────────────────── QR generation & verification ────────────────
def _urlsafe_b64decode(s: str) -> bytes:
    s = (s or "").strip()
    if not s: return b""
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))

def _sign_qr_token(user_id: str, exp_ts: int) -> str:
    msg = f"{user_id}.{exp_ts}".encode("utf-8")
    sig = hmac.new(CHECKIN_QR_SECRET.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    raw = f"{user_id}.{exp_ts}.{sig}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")

def _verify_qr_token(token: str) -> tuple[str, int]:
    now = int(datetime.now(timezone.utc).timestamp())
    def _validate(user_id: str, exp_str: str, sig_hex: str):
        if not user_id or not exp_str or not sig_hex: raise ValueError("malformed token")
        try: exp = int(str(exp_str).strip().strip("."))
        except Exception: raise ValueError("invalid expiry")
        msg = f"{user_id}.{exp}".encode("utf-8")
        expected = hmac.new(CHECKIN_QR_SECRET.encode("utf-8"), msg, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig_hex): raise ValueError("bad signature")
        if exp < now: raise ValueError("token expired")
        return user_id, exp

    tok = (token or "").strip()
    try:
        raw = _urlsafe_b64decode(tok).decode("utf-8")
        parts = raw.split(".", 2)
        if len(parts) == 3: return _validate(parts[0], parts[1], parts[2])
    except Exception: pass

    if tok.count(".") >= 2:
        try:
            parts = tok.split(".", 2)
            return _validate(parts[0], parts[1], parts[2])
        except Exception: pass
    raise ValueError("invalid token")

@user_bp.get("/api/checkins/qr-token")
@auth_required
def get_qr_token():
    exp_ts = int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp())
    return jsonify({"token": _sign_qr_token(g.user_id, exp_ts), "expires_at": exp_ts})

# ───────────────────────── QR scanner (public/door) ─────────────────────
@user_bp.post("/api/checkins/scan")
def public_qr_scan():
    body = request.get_json(force=True, silent=True) or {}
    token = (body.get("token") or "").strip()
    if not token: return err("token required", 400)

    try: user_id, exp_ts = _verify_qr_token(token)
    except ValueError as e: return err(str(e), 400)
    except Exception: return err("verification failed", 400)

    had_access_before = has_access_now_for_subject(user_id, None)
    sync_info = None

    if not had_access_before:
        try: sync_info = sync_stripe_for_user(user_id, min_age_seconds=300, force=False)
        except Exception as e: sync_info = {"ok": False, "error": "sync failed"}

    has_access_after = has_access_now_for_subject(user_id, None)

    rec = record_checkin(
        subject_type="user", subject_id=user_id, method="qr",
        location=body.get("location"), source=body.get("source"),
        meta={"exp": exp_ts, "access_before": had_access_before, "access_after": has_access_after, "sync": sync_info}
    )

    user_display = {}
    try:
        prof = sb_admin.table("user_profiles").select("first_name,last_name,email").eq("user_id", user_id).limit(1).execute().data
        if prof: user_display = prof[0]
    except Exception: pass

    return jsonify({"ok": True, "checkin": rec, "user": user_display, "sync": sync_info})

# ───────────────────────── dashboard endpoints ─────────────────────────
@user_bp.get("/api/plans")
def list_plans():
    try:
        rows = sb_admin.table("membership_plans").select("id,slug,name,description,price_cents,currency,interval,interval_count,stripe_price_id,stripe_checkout_mode").eq("is_active", True).order("price_cents", desc=False).execute().data
        return jsonify(rows)
    except Exception as e: return err(f"failed to load plans: {e}", 500)

@user_bp.get("/api/access/status")
@auth_required
def access_status():
    subject_type = (request.args.get("subjectType") or "user").lower()
    subject_id = g.user_id if subject_type == "user" else request.args.get("subjectId")
    if not subject_id: return err("subjectId required", 400)

    q = sb_admin.table("membership_periods").select("period_start,period_end").eq("is_voided", False)
    q = q.eq("subject_user_id", subject_id) if subject_type == "user" else q.eq("dependent_id", subject_id)
    now = datetime.now(timezone.utc)

    rows = q.execute().data or []
    can_enter = any(_parse_ts(r["period_start"]) <= now < _parse_ts(r["period_end"]) for r in rows)
    return jsonify({"subject_type": subject_type, "subject_id": subject_id, "can_enter": can_enter})

@user_bp.get("/api/checkins/mine")
@auth_required
def my_checkins():
    limit = min(max(int(request.args.get("limit", "100")), 1), 200)
    rows = sb_admin.table("gym_checkins").select("id,subject_user_id,dependent_id,method,location,source,scanned_at,meta").eq("subject_user_id", g.user_id).order("scanned_at", desc=True).limit(limit).execute().data
    return jsonify({"items": rows, "count": len(rows)})

@user_bp.get("/api/memberships/mine/summary")
@auth_required
def my_membership_summary():
    mems = sb_admin.table("user_memberships").select("id,status,plan_id,subject_user_id,dependent_id").eq("owner_user_id", g.user_id).execute().data
    if not mems: return jsonify({"items": [], "counts_by_plan": [], "count": 0})

    plan_ids = {m["plan_id"] for m in mems if m.get("plan_id")}
    plans = sb_admin.table("membership_plans").select("id,name").in_("id", list(plan_ids)).execute().data
    plan_by_id = {p["id"]: p for p in plans}

    dep_ids = [m["dependent_id"] for m in mems if m.get("dependent_id")]
    dep_map = {}
    if dep_ids:
        deps = sb_admin.table("dependents").select("id,first_name,last_name").in_("id", dep_ids).execute().data
        dep_map = {d["id"]: f"{d.get('first_name','')} {d.get('last_name','')}".strip() for d in deps}

    items, counts_map = [], {}
    for m in mems:
        subj_type = "user" if m.get("subject_user_id") else "dependent"
        items.append({
            "id": m["id"], "status": m.get("status"),
            "plan": {"id": m["plan_id"], "name": plan_by_id.get(m["plan_id"], {}).get("name")},
            "subject_type": subj_type, "subject_id": m.get("subject_user_id") or m.get("dependent_id"),
            "subject_label": "Me" if subj_type == "user" else dep_map.get(m.get("dependent_id"), "Dependent"),
        })
        if m.get("status") in ("active", "trialing"):
            counts_map[m["plan_id"]] = counts_map.get(m["plan_id"], 0) + 1

    counts_by_plan = [{"plan_id": pid, "plan_name": plan_by_id.get(pid, {}).get("name"), "count_active": n} for pid, n in counts_map.items()]
    return jsonify({"items": items, "counts_by_plan": counts_by_plan, "count": len(items)})

@user_bp.get("/api/family/dependents")
@auth_required
def list_my_dependents():
    links = sb_admin.table("guardian_links").select("dependent_id,relationship,is_primary").eq("guardian_user_id", g.user_id).execute().data
    dep_ids = [l["dependent_id"] for l in links]
    if not dep_ids: return jsonify({"items": [], "count": 0})

    deps = sb_admin.table("dependents").select("id,first_name,last_name,date_of_birth,email").in_("id", dep_ids).order("first_name", desc=False).execute().data
    by_id = {d["id"]: d for d in deps}
    for l in links:
        if l["dependent_id"] in by_id:
            by_id[l["dependent_id"]].update({"relationship": l.get("relationship"), "is_primary": l.get("is_primary")})
            
    items = list(by_id.values())
    return jsonify({"items": items, "count": len(items)})