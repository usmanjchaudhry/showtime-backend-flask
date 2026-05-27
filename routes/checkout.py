# routes/checkout.py
import stripe
from flask import Blueprint, request, jsonify, g
from datetime import datetime, timezone

from core import (
    sb_admin, STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, FRONTEND_URL,
    err, log, auth_required, add_interval, ensure_membership
)

checkout_bp = Blueprint('checkout', __name__)

# ───────────────────────── stripe helpers ──────────────────────────
def get_or_create_stripe_customer(user_id: str) -> str:
    prof = sb_admin.table("user_profiles").select("stripe_customer_id,email,first_name,last_name").eq("user_id", user_id).limit(1).execute().data
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
    log.info(f"[{getattr(g, '_rid', '-')}] created stripe customer {cid} for user {user_id}")
    return cid

def ensure_one_time_period_from_meta(meta: dict, *, external_id: str, created_ts: int | None, amount_total: int | None, currency: str | None) -> tuple[dict, bool]:
    plan_id = (meta.get("plan_id") or "").strip()
    owner_user_id = (meta.get("owner_user_id") or "").strip()
    subject_user_id = (meta.get("subject_user_id") or "").strip() or None
    dependent_id = (meta.get("dependent_id") or "").strip() or None

    if not (plan_id and owner_user_id):
        raise ValueError("session metadata missing plan_id or owner_user_id")

    plan_rows = sb_admin.table("membership_plans").select("id,interval,interval_count").eq("id", plan_id).limit(1).execute().data
    if not plan_rows:
        raise ValueError("plan not found")
    plan = plan_rows[0]

    subject_uid = subject_user_id or (owner_user_id if not dependent_id else None)
    mem = ensure_membership(
        owner_user_id=owner_user_id, plan_id=plan_id, subject_user_id=subject_uid,
        dependent_id=dependent_id, status="active"
    )

    exists = sb_admin.table("membership_periods").select("id").eq("source", "stripe").eq("source_ref", external_id).limit(1).execute().data

    created_period = False
    if not exists:
        # ✅ FIX: Safely convert Stripe's Unix integer timestamp
        start = datetime.fromtimestamp(int(created_ts), tz=timezone.utc) if created_ts else datetime.now(timezone.utc)
        end = add_interval(start, plan.get("interval") or "day", plan.get("interval_count") or 1)

        sb_admin.table("membership_periods").insert({
            "user_membership_id": mem["id"],
            "owner_user_id": mem["owner_user_id"],
            "subject_user_id": mem.get("subject_user_id"),
            "dependent_id": mem.get("dependent_id"),
            "plan_id": mem["plan_id"],
            "source": "stripe",
            "source_ref": external_id,
            "period_start": start.isoformat(),
            "period_end": end.isoformat(),
        }).execute()
        created_period = True

    if amount_total is not None:
        rec_existing = sb_admin.table("payment_receipts").select("id").eq("source", "stripe").eq("external_id", external_id).limit(1).execute().data
        if not rec_existing:
            sb_admin.table("payment_receipts").insert({
                "user_membership_id": mem["id"], "owner_user_id": mem["owner_user_id"],
                "subject_user_id": mem.get("subject_user_id"), "dependent_id": mem.get("dependent_id"),
                "plan_id": mem["plan_id"], "source": "stripe", "external_type": "checkout_session",
                "external_id": external_id, "status": "succeeded", "amount_cents": int(amount_total or 0),
                "currency": (currency or "USD").upper(), "paid_at": datetime.now(timezone.utc).isoformat(),
            }).execute()

    sb_admin.table("user_memberships").update({"status": "active"}).eq("id", mem["id"]).execute()
    return mem, created_period

# ───────────────────────── checkout endpoints ──────────────────────────
@checkout_bp.get("/api/checkout/session-info")
@auth_required
def checkout_session_info():
    sid = (request.args.get("session_id") or "").strip()
    if not sid: return err("session_id required", 400)

    try: sess = stripe.checkout.Session.retrieve(sid)
    except Exception as e: return err(f"invalid session_id: {e}", 400)

    md = (sess.get("metadata") or {}) if isinstance(sess, dict) else getattr(sess, "metadata", {}) or {}
    owner_user_id = md.get("owner_user_id")
    if owner_user_id and owner_user_id != g.user_id: return err("forbidden", 403)

    plan_id = md.get("plan_id")
    plan = None
    if plan_id:
        rows = sb_admin.table("membership_plans").select("id,name,price_cents,currency,interval,interval_count").eq("id", plan_id).limit(1).execute().data
        plan = rows[0] if rows else None

    subj_type = "user"
    subj_id = md.get("subject_user_id") or None
    if not subj_id:
        subj_type = "dependent"
        subj_id = md.get("dependent_id")
    
    subject_label = "Me"
    if subj_type == "dependent" and subj_id:
        dep_rows = sb_admin.table("dependents").select("first_name,last_name").eq("id", subj_id).limit(1).execute().data
        if dep_rows:
            fn, ln = (dep_rows[0].get("first_name") or "").strip(), (dep_rows[0].get("last_name") or "").strip()
            subject_label = (fn + " " + ln).strip() or "Dependent"

    return jsonify({
        "mode": sess.get("mode"), "status": sess.get("status"),
        "amount_total": sess.get("amount_total"), "currency": (sess.get("currency") or "usd").upper(),
        "plan": plan, "subject": {"type": subj_type, "id": subj_id, "label": subject_label},
    })

@checkout_bp.post("/api/checkout/session")
@auth_required
def create_checkout_session():
    rid = getattr(g, "_rid", "-")
    if not STRIPE_SECRET_KEY: return err("stripe not configured", 500)

    body = request.get_json(force=True, silent=True) or {}
    plan_id, plan_slug = body.get("plan_id"), body.get("plan_slug")
    subject_type = (body.get("subject_type") or "user").lower()
    subject_id = body.get("subject_id")

    if subject_type not in ("user", "dependent"): return err("subject_type must be 'user' or 'dependent'", 400)
    if subject_type == "user": subject_id = g.user_id
    elif not subject_id: return err("subject_id required for dependent", 400)

    if plan_id: sel = sb_admin.table("membership_plans").select("*").eq("id", plan_id).eq("is_active", True).limit(1)
    elif plan_slug: sel = sb_admin.table("membership_plans").select("*").eq("slug", plan_slug).eq("is_active", True).limit(1)
    else: return err("plan_id or plan_slug required", 400)

    plans = sel.execute().data
    if not plans: return err("plan not found or inactive", 404)
    plan = plans[0]
    
    price_id = plan.get("stripe_price_id")
    if not price_id: return err("plan missing stripe_price_id", 400)

    checkout_mode = (plan.get("stripe_checkout_mode") or "subscription").lower()
    customer_id = get_or_create_stripe_customer(g.user_id)

    md = {
        "owner_user_id": g.user_id, "plan_id": plan["id"],
        "subject_user_id": g.user_id if subject_type == "user" else "",
        "dependent_id": subject_id if subject_type == "dependent" else "",
    }

    base = FRONTEND_URL or "http://localhost:5173"
    success_url = f"{base}/purchase?session_id={{CHECKOUT_SESSION_ID}}"
    cancel_url = f"{base}/purchase"

    try:
        if checkout_mode == "subscription":
            sess = stripe.checkout.Session.create(
                mode="subscription", line_items=[{"price": price_id, "quantity": 1}],
                customer=customer_id, success_url=success_url, cancel_url=cancel_url,
                metadata=md, subscription_data={"metadata": md},
            )
        else:
            sess = stripe.checkout.Session.create(
                mode="payment", line_items=[{"price": price_id, "quantity": 1}],
                customer=customer_id, success_url=success_url, cancel_url=cancel_url, metadata=md,
            )
        log.info(f"[{rid}] stripe session created id={sess.id}")
    except Exception as e:
        log.error(f"[{rid}] stripe error: {e}")
        return err(f"stripe checkout error: {e}", 400)

    return jsonify({"checkout_url": sess.url})

@checkout_bp.post("/api/checkout/finalize")
@auth_required
def checkout_finalize():
    if not STRIPE_SECRET_KEY: return err("stripe not configured", 500)
    body = request.get_json(force=True, silent=True) or {}
    sid = (body.get("session_id") or body.get("sessionId") or "").strip()
    if not sid: return err("session_id required", 400)

    try: sess = stripe.checkout.Session.retrieve(sid)
    except Exception as e: return err(f"invalid session_id: {e}", 400)

    md = sess.get("metadata", {}) or {}
    owner_user_id = (md.get("owner_user_id") or "").strip()
    if not owner_user_id or owner_user_id != g.user_id: return err("forbidden", 403)
    if sess.get("status") != "complete" and sess.get("payment_status") != "paid": return err("checkout session not complete yet", 409)

    mode = (sess.get("mode") or "").lower()
    customer_id = sess.get("customer")
    plan_id = (md.get("plan_id") or "").strip()
    if not plan_id: return err("missing plan_id in session metadata", 400)

    subject_user_id = (md.get("subject_user_id") or "").strip() or None
    dependent_id = (md.get("dependent_id") or "").strip() or None
    if not subject_user_id and not dependent_id: subject_user_id = owner_user_id

    if mode == "subscription":
        sub_id = sess.get("subscription")
        if not sub_id: return err("subscription missing on session", 400)
        try: sub = stripe.Subscription.retrieve(sub_id)
        except Exception as e: return err(f"could not retrieve subscription: {e}", 400)

        sub_status = (sub.get("status") or "").lower()
        mapped_status = "active" if sub_status in ("active", "trialing") else "canceled" if sub_status in ("canceled", "incomplete_expired") else "past_due"

        mem = ensure_membership(
            owner_user_id=owner_user_id, plan_id=plan_id, subject_user_id=subject_user_id,
            dependent_id=dependent_id, provider_customer_id=customer_id,
            provider_subscription_id=sub_id, status=mapped_status,
        )

        created_period = False
        start_ts, end_ts = sub.get("current_period_start"), sub.get("current_period_end")
        if start_ts and end_ts:
            src_ref = f"{sub_id}:{int(start_ts)}"
            exists = sb_admin.table("membership_periods").select("id").eq("source", "stripe").eq("source_ref", src_ref).limit(1).execute().data
            if not exists:
                sb_admin.table("membership_periods").insert({
                    "user_membership_id": mem["id"], "owner_user_id": mem["owner_user_id"],
                    "subject_user_id": mem.get("subject_user_id"), "dependent_id": mem.get("dependent_id"),
                    "plan_id": mem["plan_id"], "source": "stripe", "source_ref": src_ref,
                    # ✅ FIX: Safely parse Stripe Timestamps
                    "period_start": datetime.fromtimestamp(int(start_ts), tz=timezone.utc).isoformat(),
                    "period_end": datetime.fromtimestamp(int(end_ts), tz=timezone.utc).isoformat(),
                }).execute()
                created_period = True

        sb_admin.table("user_memberships").update({"status": mapped_status}).eq("id", mem["id"]).execute()
        return jsonify({"ok": True, "mode": "subscription", "membership_id": mem["id"], "status": mapped_status, "customer_id": customer_id, "subscription_id": sub_id, "period_backfilled": created_period})

    if mode == "payment":
        try:
            mem, created_period = ensure_one_time_period_from_meta(
                md, external_id=sess.get("id"), created_ts=sess.get("created"),
                amount_total=sess.get("amount_total"), currency=sess.get("currency")
            )
        except Exception as e:
            return err(f"finalize failed: {e}", 400)
        return jsonify({"ok": True, "mode": "payment", "membership_id": mem["id"], "status": "active", "customer_id": customer_id, "subscription_id": None, "period_backfilled": created_period})

    return err("unsupported checkout mode", 400)

# ───────────────────────── stripe webhooks ──────────────────────────
@checkout_bp.post("/webhooks/stripe")
def stripe_webhook():
    if not STRIPE_WEBHOOK_SECRET: return err("webhook not configured", 500)

    # ✅ FIX: Use get_data() to preserve raw byte string for signature validation
    payload = request.get_data(as_text=True)
    sig = request.headers.get("Stripe-Signature", "")
    try: 
        event = stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)
    except Exception as e: 
        log.error(f"Webhook signature failed: {e}")
        return err(f"webhook signature failed: {e}", 400)

    etype = event["type"]
    log.info(f"Stripe Webhook Event: {etype}")

    if etype == "checkout.session.completed":
        sess = event["data"]["object"]
        mode = sess.get("mode")
        customer_id = sess.get("customer")
        md = sess.get("metadata", {}) or {}
        plan_id, owner_user_id = md.get("plan_id"), md.get("owner_user_id")
        subject_user_id, dependent_id = md.get("subject_user_id") or None, md.get("dependent_id") or None

        if mode == "subscription":
            sub_id = sess.get("subscription")
            if not (plan_id and owner_user_id and sub_id and customer_id): return jsonify({"ok": True})
            mem = ensure_membership(
                owner_user_id=owner_user_id, plan_id=plan_id, subject_user_id=subject_user_id,
                dependent_id=dependent_id, provider_customer_id=customer_id,
                provider_subscription_id=sub_id, status="active"
            )
            try:
                sub = stripe.Subscription.retrieve(sub_id)
                start_ts, end_ts = sub.get("current_period_start"), sub.get("current_period_end")
                if start_ts and end_ts:
                    src_ref = f"{sub_id}:{start_ts}"
                    exists = sb_admin.table("membership_periods").select("id").eq("source", "stripe").eq("source_ref", src_ref).limit(1).execute().data
                    if not exists:
                        sb_admin.table("membership_periods").insert({
                            "user_membership_id": mem["id"], "owner_user_id": mem["owner_user_id"],
                            "subject_user_id": mem.get("subject_user_id"), "dependent_id": mem.get("dependent_id"),
                            "plan_id": mem["plan_id"], "source": "stripe", "source_ref": src_ref,
                            # ✅ FIX: Safely parse Stripe Timestamps
                            "period_start": datetime.fromtimestamp(int(start_ts), tz=timezone.utc).isoformat(),
                            "period_end": datetime.fromtimestamp(int(end_ts), tz=timezone.utc).isoformat(),
                        }).execute()
            except Exception as e:
                log.warning(f"could not seed period from subscription: {e}")
            return jsonify({"ok": True})

        if mode == "payment":
            ensure_one_time_period_from_meta(md, external_id=sess.get("id"), created_ts=sess.get("created"), amount_total=sess.get("amount_total"), currency=sess.get("currency"))
            return jsonify({"ok": True})

    if etype == "invoice.paid":
        inv = event["data"]["object"]
        sub_id = inv.get("subscription")
        invoice_id = inv.get("id")
        mem_rows = sb_admin.table("user_memberships").select("*").eq("provider_subscription_id", sub_id).limit(1).execute().data
        if not mem_rows: return jsonify({"ok": True})
        mem = mem_rows[0]

        lines = inv.get("lines", {}).get("data", [])
        if not lines: return jsonify({"ok": True})
        start_ts, end_ts = lines[0].get("period", {}).get("start"), lines[0].get("period", {}).get("end")
        if not (start_ts and end_ts): return jsonify({"ok": True})

        existing = sb_admin.table("membership_periods").select("id").eq("source", "stripe").eq("source_ref", invoice_id).limit(1).execute().data
        if not existing:
            sb_admin.table("membership_periods").insert({
                "user_membership_id": mem["id"], "owner_user_id": mem["owner_user_id"],
                "subject_user_id": mem.get("subject_user_id"), "dependent_id": mem.get("dependent_id"),
                "plan_id": mem["plan_id"], "source": "stripe", "source_ref": invoice_id,
                # ✅ FIX: Safely parse Stripe Timestamps
                "period_start": datetime.fromtimestamp(int(start_ts), tz=timezone.utc).isoformat(),
                "period_end": datetime.fromtimestamp(int(end_ts), tz=timezone.utc).isoformat(),
            }).execute()

        rec_existing = sb_admin.table("payment_receipts").select("id").eq("source", "stripe").eq("external_id", invoice_id).limit(1).execute().data
        if not rec_existing:
            sb_admin.table("payment_receipts").insert({
                "user_membership_id": mem["id"], "owner_user_id": mem["owner_user_id"],
                "subject_user_id": mem.get("subject_user_id"), "dependent_id": mem.get("dependent_id"),
                "plan_id": mem["plan_id"], "source": "stripe", "external_type": "invoice",
                "external_id": invoice_id, "status": "succeeded", "amount_cents": int(inv.get("amount_paid") or 0),
                "currency": (inv.get("currency") or "usd").upper(), "paid_at": datetime.now(timezone.utc).isoformat(),
            }).execute()

        sb_admin.table("user_memberships").update({"status": "active"}).eq("id", mem["id"]).execute()
        return jsonify({"ok": True})

    if etype in ("invoice.payment_failed",):
        sub_id = event["data"]["object"].get("subscription")
        sb_admin.table("user_memberships").update({"status": "past_due"}).eq("provider_subscription_id", sub_id).execute()
        return jsonify({"ok": True})

    if etype in ("customer.subscription.deleted",):
        sub = event["data"]["object"]
        patch = {"status": "canceled"}
        if sub.get("current_period_end"): 
            patch["current_period_end"] = datetime.fromtimestamp(int(sub.get("current_period_end")), tz=timezone.utc).isoformat()
        sb_admin.table("user_memberships").update(patch).eq("provider_subscription_id", sub.get("id")).execute()
        return jsonify({"ok": True})

    return jsonify({"ok": True})