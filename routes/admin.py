# routes/admin.py
import os
import json
import logging
from datetime import datetime, timedelta, timezone, date
from typing import Dict, List
import stripe
import requests
from flask import Blueprint, request, jsonify, g

from core import (
    sb_admin, err, log, auth_required, admin_required, _parse_ts, 
    to_utc_ts, record_checkin, ensure_membership, stripe_customer_dashboard_url,
    add_interval 
)

try:
    from zoneinfo import ZoneInfo
except Exception:
    ZoneInfo = None

admin_bp = Blueprint("admin", __name__)

REPORT_TZ_NAME = (os.getenv("REPORT_TZ") or "America/Los_Angeles").strip()
if ZoneInfo:
    try: REPORT_TZ = ZoneInfo(REPORT_TZ_NAME)
    except Exception: REPORT_TZ = timezone.utc
else:
    REPORT_TZ = timezone.utc

# ────────────────────────── date helpers ──────────────────────────
def _parse_yyyy_mm_dd(s: str) -> date:
    return datetime.strptime(s, "%Y-%m-%d").date()

def _start_of_day(d: date) -> datetime:
    return datetime(d.year, d.month, d.day, 0, 0, 0, tzinfo=REPORT_TZ)

def _end_of_day_inclusive(d: date) -> datetime:
    return _start_of_day(d + timedelta(days=1)) - timedelta(microseconds=1)

def _daterange(start_d: date, end_d: date):
    cur = start_d
    while cur <= end_d:
        yield cur
        cur = cur + timedelta(days=1)

def _compute_range(period: str | None, start_str: str | None, end_str: str | None):
    now = datetime.now(REPORT_TZ)
    period = (period or "30d").lower().strip()

    if start_str and end_str:
        s, e = _parse_yyyy_mm_dd(start_str), _parse_yyyy_mm_dd(end_str)
        if s > e: raise ValueError("start must be <= end")
        start_dt, end_dt = _start_of_day(s), min(_end_of_day_inclusive(e), now)
        return ("custom", start_dt, end_dt, f"{s.isoformat()} → {end_dt.date().isoformat()}")

    if period == "today":
        d = now.date()
        return ("today", _start_of_day(d), now, d.isoformat())

    if period == "7d":
        start_dt = _start_of_day((now - timedelta(days=6)).date())
        return ("7d", start_dt, now, f"{start_dt.date().isoformat()} → {now.date().isoformat()}")

    if period == "mtd":
        start_dt = datetime(now.year, now.month, 1, 0, 0, 0, tzinfo=REPORT_TZ)
        return ("mtd", start_dt, now, f"{start_dt.date().isoformat()} → {now.date().isoformat()}")

    if period == "ytd":
        start_dt = datetime(now.year, 1, 1, 0, 0, 0, tzinfo=REPORT_TZ)
        return ("ytd", start_dt, now, f"{start_dt.date().isoformat()} → {now.date().isoformat()}")

    start_dt = _start_of_day((now - timedelta(days=29)).date())
    return ("30d", start_dt, now, f"{start_dt.date().isoformat()} → {now.date().isoformat()}")

# ────────────────────────── revenue endpoint ──────────────────────────
@admin_bp.get("/api/admin/revenue")
@auth_required
@admin_required
def get_revenue():
    if not stripe.api_key: return err("Stripe not configured", 500)

    period = request.args.get("period", "30d")
    start_str, end_str = request.args.get("start"), request.args.get("end")

    try: resolved_period, start_dt, end_dt, label = _compute_range(period, start_str, end_str)
    except Exception as e: return err(f"Invalid date range: {e}", 400)

    daily = {
        d.isoformat(): {
            "date": d.isoformat(), "gross_cents": 0, "fees_cents": 0, "refunds_cents": 0,
            "net_cents": 0, "charges_count": 0, "refunds_count": 0,
        } for d in _daterange(start_dt.date(), end_dt.date())
    }

    total_gross = total_fees = total_refunds = total_net = charges_count = refunds_count = 0
    currencies, ignored_categories = set(), {}

    try:
        bts = stripe.BalanceTransaction.list(created={"gte": int(start_dt.timestamp()), "lte": int(end_dt.timestamp())}, limit=100)
        for bt in bts.auto_paging_iter():
            cat = (bt.get("reporting_category") or bt.get("type") or "").lower().strip()
            amount, fee, net = int(bt.get("amount") or 0), int(bt.get("fee") or 0), int(bt.get("net") or 0)
            currencies.add((bt.get("currency") or "usd").upper())

            day_key = datetime.fromtimestamp(int(bt.get("created") or 0), tz=timezone.utc).astimezone(REPORT_TZ).date().isoformat()
            if day_key not in daily:
                daily[day_key] = {"date": day_key, "gross_cents": 0, "fees_cents": 0, "refunds_cents": 0, "net_cents": 0, "charges_count": 0, "refunds_count": 0}

            if cat in ("charge", "payment"):
                daily[day_key]["gross_cents"] += amount
                daily[day_key]["fees_cents"] += fee
                daily[day_key]["net_cents"] += net
                daily[day_key]["charges_count"] += 1
                total_gross += amount; total_fees += fee; total_net += net; charges_count += 1
            elif cat in ("refund",):
                daily[day_key]["refunds_cents"] += abs(amount)
                daily[day_key]["fees_cents"] += fee
                daily[day_key]["net_cents"] += net
                daily[day_key]["refunds_count"] += 1
                total_refunds += abs(amount); total_fees += fee; total_net += net; refunds_count += 1
            else:
                ignored_categories[cat or "unknown"] = ignored_categories.get(cat or "unknown", 0) + 1

        try:
            recent_payouts = stripe.Payout.list(limit=20).data
            expected_payout = 0
            received_today = 0
            today_date = datetime.now(REPORT_TZ).date()
            for p in recent_payouts:
                arr_date = datetime.fromtimestamp(p.arrival_date, tz=timezone.utc).astimezone(REPORT_TZ).date()
                if p.status in ("pending", "in_transit"):
                    expected_payout += p.amount / 100
                elif p.status == "paid" and arr_date == today_date:
                    received_today += p.amount / 100

            disputes_count = len(stripe.Dispute.list(status='needs_response', limit=10).data)

            failed_payments = []
            for c in stripe.Charge.list(limit=50).data:
                if c.status == 'failed':
                    bd = getattr(c, "billing_details", None)
                    failed_payments.append({
                        "id": c.id, "amount": c.amount / 100,
                        "email": (bd.email if bd else None) or c.receipt_email or "No Email",
                        "name": (bd.name if bd else None) or "Unknown Customer",
                        "phone": (bd.phone if bd else None) or "",
                        "date": datetime.fromtimestamp(c.created, tz=timezone.utc).isoformat()
                    })
                    if len(failed_payments) >= 10: break
        except Exception as extra_e:
            log.warning(f"Extras fetch failed: {extra_e}")
            expected_payout = received_today = disputes_count = 0
            failed_payments = []

        currency_out = "MIXED" if len(currencies) > 1 else (next(iter(currencies)) if currencies else "USD")
        breakdown = [{"date": v["date"], "gross": v["gross_cents"] / 100, "fees": v["fees_cents"] / 100, "refunds": v["refunds_cents"] / 100, "net": v["net_cents"] / 100, "charges_count": v["charges_count"], "refunds_count": v["refunds_count"]} for _, v in sorted(daily.items())]

        return jsonify({
            "ok": True, "period": resolved_period, "currency": currency_out,
            "received_today": received_today, "expected_payout": expected_payout,
            "disputes_count": disputes_count, "failed_payments": failed_payments,
            "range": {"label": label, "start": start_dt.date().isoformat(), "end": end_dt.date().isoformat(), "timezone": REPORT_TZ_NAME, "days": (end_dt.date() - start_dt.date()).days + 1, "generated_at": datetime.now(timezone.utc).isoformat()},
            "totals": {"gross": total_gross / 100, "fees": total_fees / 100, "refunds": total_refunds / 100, "net": total_net / 100, "charges_count": charges_count, "refunds_count": refunds_count},
            "breakdown": breakdown, "meta": {"ignored_categories": ignored_categories}
        })
    except Exception as e:
        log.exception("Stripe revenue error")
        return err(f"Stripe Error: {e}", 500)

@admin_bp.post("/api/admin/checkins")
@auth_required
@admin_required
def admin_checkin():
    body = request.get_json(force=True, silent=True) or {}
    subject_type, subject_id = (body.get("subject_type") or "user").lower(), body.get("subject_id")
    if subject_type not in ("user", "dependent") or not subject_id: return err("subject_type and subject_id required", 400)
    rec = record_checkin(subject_type=subject_type, subject_id=subject_id, method=body.get("method") or "admin", location=body.get("location"), source=body.get("source") or f"admin:{g.user_id}", meta=body.get("meta") or {})
    return jsonify({"ok": True, "checkin": rec})

@admin_bp.post("/api/admin/periods")
@auth_required
@admin_required
def admin_add_period():
    body = request.get_json(force=True, silent=True) or {}
    user_membership_id, owner_user_id = body.get("user_membership_id"), (body.get("owner_user_id") or g.user_id)
    subject_type, subject_id = (body.get("subject_type") or "user").lower(), body.get("subject_id")
    plan_id, period_start_iso, period_end_iso = (body.get("plan_id") or "").strip(), body.get("period_start"), body.get("period_end")
    
    amount_cents = body.get("amount_cents")
    notes = body.get("notes") or "Paid in cash at front desk"

    if not plan_id or not period_start_iso or not period_end_iso: return err("period_start, period_end, plan_id required", 400)
    try: ps, pe = _parse_ts(period_start_iso), _parse_ts(period_end_iso)
    except Exception: return err("Invalid datetime format", 400)
    if ps >= pe: return err("period_start must be before period_end", 400)
    
    try:
        mem = sb_admin.table("user_memberships").select("*").eq("id", user_membership_id).limit(1).execute().data[0] if user_membership_id else None
        if not mem: mem = ensure_membership(owner_user_id=owner_user_id, plan_id=plan_id, subject_user_id=(owner_user_id if subject_type == "user" else None), dependent_id=(subject_id if subject_type == "dependent" else None), status="active")
        
        # 1. Insert Door Scanner Ticket
        ins = sb_admin.table("membership_periods").insert({
            "user_membership_id": mem["id"], "owner_user_id": mem["owner_user_id"], 
            "subject_user_id": mem.get("subject_user_id"), "dependent_id": mem.get("dependent_id"), 
            "plan_id": mem["plan_id"], "source": "manual", "period_start": ps.isoformat(), 
            "period_end": pe.isoformat()
        }).execute().data[0]
        
        # 2. Update Master Folder and explicitly mark as Cash
        sb_admin.table("user_memberships").update({
            "status": "active",
            "payment_provider": "cash",
            "current_period_start": ps.isoformat(),
            "current_period_end": pe.isoformat()
        }).eq("id", mem["id"]).execute()

        # 3. Log Financial Receipt
        if amount_cents is not None:
            sb_admin.table("payment_receipts").insert({
                "user_membership_id": mem["id"], "owner_user_id": mem["owner_user_id"],
                "subject_user_id": mem.get("subject_user_id"), "dependent_id": mem.get("dependent_id"),
                "plan_id": plan_id, "source": "manual", "external_type": "cash",
                "status": "succeeded", "amount_cents": amount_cents, "currency": "USD",
                "notes": notes, "paid_at": ps.isoformat(), "created_by_user_id": g.user_id
            }).execute()

        return jsonify({"ok": True, "membership_period_id": ins["id"]})
    except Exception as e: return err(f"Operation failed: {e}", 400)

@admin_bp.get("/api/admin/users/overview")
@auth_required
@admin_required
def admin_users_overview():
    now = datetime.now(timezone.utc)
    try:
        users = sb_admin.table("user_profiles").select("user_id,email,first_name,last_name,stripe_customer_id").order("first_name", desc=False).execute().data
        owner_ids = [u["user_id"] for u in users if u.get("user_id")]
        
        # ✅ FIX: Fetch payment_provider, start, and end dates
        memberships = sb_admin.table("user_memberships").select("id,owner_user_id,subject_user_id,dependent_id,plan_id,status,payment_provider,current_period_start,current_period_end").in_("owner_user_id", owner_ids).execute().data if owner_ids else []
        
        plans = {p["id"]: p for p in sb_admin.table("membership_plans").select("id,name,price_cents,currency,interval,interval_count").in_("id", list({m["plan_id"] for m in memberships})).execute().data} if memberships else {}
        periods_by_owner = {oid: [] for oid in owner_ids}
        if owner_ids:
            for r in sb_admin.table("membership_periods").select("owner_user_id,period_start,period_end").in_("owner_user_id", owner_ids).eq("is_voided", False).execute().data:
                periods_by_owner.setdefault(r["owner_user_id"], []).append(r)
        def active_now(periods):
            for pr in periods or []:
                try:
                    if _parse_ts(pr["period_start"]) <= now < _parse_ts(pr["period_end"]): return True
                except Exception: continue
            return False
            
        last_checkin_by_subject = {row["subject_user_id"]: row["scanned_at"] for row in sb_admin.table("gym_checkins").select("subject_user_id,scanned_at").in_("subject_user_id", owner_ids).order("scanned_at", desc=True).execute().data} if owner_ids else {}
        
        # ✅ FIX: Fetch Last Payment date from receipts
        latest_payment_map = {}
        latest_payment_amount_map = {} 
        if owner_ids:
            recent_payments = sb_admin.table("payment_receipts").select("owner_user_id, paid_at, amount_cents").in_("owner_user_id", owner_ids).order("paid_at", desc=True).execute().data
            for p in recent_payments:
                if p["owner_user_id"] not in latest_payment_map:
                    latest_payment_map[p["owner_user_id"]] = p["paid_at"]
                    latest_payment_amount_map[p["owner_user_id"]] = p["amount_cents"]

        active_w = sb_admin.table("waivers").select("id,version").eq("is_active", True).eq("required_for_purchase", True).limit(1).execute().data
        waiver_required = bool(active_w)
        signed_subjects = {s["subject_user_id"] for s in sb_admin.table("waiver_signatures").select("subject_user_id").eq("waiver_id", active_w[0]["id"]).eq("waiver_version", active_w[0]["version"]).is_("revoked_at", "null").in_("subject_user_id", owner_ids).execute().data} if waiver_required and owner_ids else set()
        mems_by_owner = {}
        for m in memberships: mems_by_owner.setdefault(m["owner_user_id"], []).append(m)
        
        # ✅ FIX: Map all new data to frontend output
        out_rows = [{
            "user_id": u["user_id"], 
            "email": u.get("email"), 
            "first_name": u.get("first_name"), 
            "last_name": u.get("last_name"), 
            "last_checkin_at": last_checkin_by_subject.get(u["user_id"]), 
            "last_payment_at": latest_payment_map.get(u["user_id"]),
            "last_payment_amount": latest_payment_amount_map.get(u["user_id"]),
            "has_access_now": active_now(periods_by_owner.get(u["user_id"], [])), 
            "waiver_required": waiver_required, 
            "waiver_signed": (u["user_id"] in signed_subjects) if waiver_required else None, 
            "memberships": [{"id": m["id"], "status": m.get("status"), "payment_provider": m.get("payment_provider"), "current_period_start": m.get("current_period_start"), "current_period_end": m.get("current_period_end"), "plan": plans.get(m.get("plan_id"))} for m in mems_by_owner.get(u["user_id"], [])], 
            "stripe_customer_url": stripe_customer_dashboard_url(u.get("stripe_customer_id"))
        } for u in users]
        return jsonify({"users": out_rows, "count": len(out_rows)})
    except Exception as e: return err(f"admin overview failed: {e}", 500)

@admin_bp.get("/api/admin/checkins/recent")
@auth_required
@admin_required
def admin_recent_checkins():
    try:
        limit, since_min = min(max(int(request.args.get("limit", "50")), 1), 200), int(request.args.get("since_min", "0"))
        q = sb_admin.table("gym_checkins").select("id,subject_user_id,dependent_id,scanned_at,method,location,source,meta").order("scanned_at", desc=True).limit(limit)
        if since_min > 0: q = q.gte("scanned_at", (datetime.now(timezone.utc) - timedelta(minutes=since_min)).isoformat())
        rows = q.execute().data or []
        user_ids = sorted({r.get("subject_user_id") for r in rows if r.get("subject_user_id")})
        users_by_id = {u["user_id"]: u for u in sb_admin.table("user_profiles").select("user_id,first_name,last_name,email").in_("user_id", user_ids).execute().data} if user_ids else {}
        items = []
        for r in rows:
            su = r.get("subject_user_id")
            if su:
                prof = users_by_id.get(su, {})
                label = f"{(prof.get('first_name') or '').strip()} {(prof.get('last_name') or '').strip()}".strip() or prof.get("email") or "Member"
                items.append({
                    "id": r["id"], 
                    "scanned_at": r.get("scanned_at"), 
                    "method": r.get("method"), 
                    "location": r.get("location"), 
                    "subject_type": "user", 
                    "subject_id": su, 
                    "subject_label": label, 
                    "email": prof.get("email"),
                    "meta": r.get("meta", {}) # ✅ THE CRITICAL FIX: Explicitly passing the meta dict!
                })
        return jsonify({"items": items, "count": len(items)})
    except Exception as e: return err(f"failed to load recent check-ins: {e}", 500)

@admin_bp.post("/api/admin/mailchimp/sync-users")
@auth_required
@admin_required
def mailchimp_sync_users():
    body = request.get_json(force=True, silent=True) or {}
    mode, user_ids = (body.get("mode") or "all").lower(), body.get("user_ids") or []
    q = sb_admin.table("user_profiles").select("user_id,email,first_name,last_name,phone")
    if mode == "selected" and user_ids: q = q.in_("user_id", user_ids)
    synced, failed = 0, 0
    prefix = os.getenv("MAILCHIMP_API_KEY").split("-")[-1] if "-" in os.getenv("MAILCHIMP_API_KEY") else ""
    for r in q.execute().data or []:
        em = (r.get("email") or "").strip()
        if not em: continue
        try:
            import hashlib
            h = hashlib.md5(em.lower().encode("utf-8")).hexdigest()
            payload = {"email_address": em, "status_if_new": "subscribed", "merge_fields": {"FNAME": r.get("first_name") or "", "LNAME": r.get("last_name") or ""}}
            requests.put(f"https://{prefix}.api.mailchimp.com/3.0/lists/{os.getenv('MAILCHIMP_AUDIENCE_ID')}/members/{h}", json=payload, auth=("anystring", os.getenv("MAILCHIMP_API_KEY")), timeout=25)
            synced += 1
        except Exception: failed += 1
    return jsonify({"ok": True, "synced": synced, "failed": failed})