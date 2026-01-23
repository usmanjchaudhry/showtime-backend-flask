import os
import logging
from datetime import datetime, timedelta, timezone, date
from functools import wraps

import stripe
from flask import Blueprint, request, jsonify, g

from dotenv import load_dotenv
from supabase import create_client, Client
from supabase.lib.client_options import SyncClientOptions as ClientOptions

try:
    from zoneinfo import ZoneInfo
except Exception:
    ZoneInfo = None


# ────────────────────────── setup ──────────────────────────
load_dotenv()

log = logging.getLogger("api.admin")

admin_bp = Blueprint("admin", __name__)

stripe.api_key = (os.getenv("STRIPE_SECRET_KEY") or "").strip()

SUPABASE_URL = (os.getenv("SUPABASE_URL") or "").strip()
SERVICE_KEY = (os.getenv("SUPABASE_SERVICE_ROLE") or "").strip()
ANON_KEY = (os.getenv("SUPABASE_ANON") or "").strip()

# Reporting timezone for grouping daily results (change to your gym timezone if you want)
REPORT_TZ_NAME = (os.getenv("REPORT_TZ") or "UTC").strip()
if ZoneInfo:
    try:
        REPORT_TZ = ZoneInfo(REPORT_TZ_NAME)
    except Exception:
        REPORT_TZ_NAME = "UTC"
        REPORT_TZ = timezone.utc
else:
    REPORT_TZ_NAME = "UTC"
    REPORT_TZ = timezone.utc

if not (SUPABASE_URL and SERVICE_KEY):
    log.warning("SUPABASE_URL or SUPABASE_SERVICE_ROLE is missing; admin auth will fail.")

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


def _err(msg: str, code: int = 400):
    return jsonify({"error": str(msg)}), code


def _bearer_token() -> str | None:
    auth = request.headers.get("Authorization", "") or ""
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    return None


def auth_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        tok = _bearer_token()
        if not tok:
            return _err("missing bearer token", 401)
        try:
            res = sb_public.auth.get_user(tok)
            user = res.user
            if not user:
                return _err("invalid token", 401)
            g.user_id = user.id
            g.user_email = user.email
        except Exception as e:
            return _err(f"invalid token: {e}", 401)
        return fn(*args, **kwargs)
    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        uid = getattr(g, "user_id", None)
        if not uid:
            return _err("unauthorized", 401)

        try:
            rows = (
                sb_admin.table("user_profiles")
                .select("is_admin")
                .eq("user_id", uid)
                .limit(1)
                .execute()
                .data
            )
            is_admin = bool(rows and rows[0].get("is_admin"))
        except Exception as e:
            return _err(f"admin check failed: {e}", 500)

        if not is_admin:
            return _err("forbidden", 403)

        return fn(*args, **kwargs)
    return wrapper


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

    # Custom range takes priority if provided
    if start_str and end_str:
        s = _parse_yyyy_mm_dd(start_str)
        e = _parse_yyyy_mm_dd(end_str)
        if s > e:
            raise ValueError("start must be <= end")

        start_dt = _start_of_day(s)
        end_dt = _end_of_day_inclusive(e)
        if end_dt > now:
            end_dt = now

        return ("custom", start_dt, end_dt, f"{s.isoformat()} → {end_dt.date().isoformat()}")

    if period == "today":
        d = now.date()
        return ("today", _start_of_day(d), now, d.isoformat())

    if period == "7d":
        # inclusive: today + previous 6 calendar days
        start_dt = _start_of_day((now - timedelta(days=6)).date())
        return ("7d", start_dt, now, f"{start_dt.date().isoformat()} → {now.date().isoformat()}")

    if period == "mtd":
        start_dt = datetime(now.year, now.month, 1, 0, 0, 0, tzinfo=REPORT_TZ)
        return ("mtd", start_dt, now, f"{start_dt.date().isoformat()} → {now.date().isoformat()}")

    if period == "ytd":
        start_dt = datetime(now.year, 1, 1, 0, 0, 0, tzinfo=REPORT_TZ)
        return ("ytd", start_dt, now, f"{start_dt.date().isoformat()} → {now.date().isoformat()}")

    # default 30d inclusive: today + previous 29 calendar days
    start_dt = _start_of_day((now - timedelta(days=29)).date())
    return ("30d", start_dt, now, f"{start_dt.date().isoformat()} → {now.date().isoformat()}")


# ────────────────────────── revenue endpoint ──────────────────────────
@admin_bp.route("/revenue", methods=["GET"])
@auth_required
@admin_required
def get_revenue():
    if not stripe.api_key:
        return _err("Stripe not configured (STRIPE_SECRET_KEY missing)", 500)

    period = request.args.get("period", "30d")
    start_str = request.args.get("start")  # YYYY-MM-DD
    end_str = request.args.get("end")      # YYYY-MM-DD

    try:
        resolved_period, start_dt, end_dt, label = _compute_range(period, start_str, end_str)
    except Exception as e:
        return _err(f"Invalid date range: {e}", 400)

    start_ts = int(start_dt.timestamp())
    end_ts = int(end_dt.timestamp())

    # Pre-fill days so UI always gets continuous rows (including $0 days)
    daily = {
        d.isoformat(): {
            "date": d.isoformat(),
            "gross_cents": 0,       # charges before fees
            "fees_cents": 0,        # stripe fees
            "refunds_cents": 0,     # refunded amount (positive)
            "net_cents": 0,         # after fees & refunds
            "charges_count": 0,
            "refunds_count": 0,
        }
        for d in _daterange(start_dt.date(), end_dt.date())
    }

    total_gross = 0
    total_fees = 0
    total_refunds = 0
    total_net = 0
    charges_count = 0
    refunds_count = 0

    currencies = set()
    ignored_categories: dict[str, int] = {}

    # We use Balance Transactions because they contain fee + net fields.
    # This is the best way to compute “revenue after Stripe fees”.
    try:
        bts = stripe.BalanceTransaction.list(
            created={"gte": start_ts, "lte": end_ts},
            limit=100,
        )

        for bt in bts.auto_paging_iter():
            cat = (bt.get("reporting_category") or bt.get("type") or "").lower().strip()
            amount = int(bt.get("amount") or 0)  # may be negative (refunds)
            fee = int(bt.get("fee") or 0)
            net = int(bt.get("net") or 0)
            currency = (bt.get("currency") or "usd").upper()
            currencies.add(currency)

            created = int(bt.get("created") or 0)
            day_key = datetime.fromtimestamp(created, tz=timezone.utc).astimezone(REPORT_TZ).date().isoformat()
            if day_key not in daily:
                daily[day_key] = {
                    "date": day_key,
                    "gross_cents": 0,
                    "fees_cents": 0,
                    "refunds_cents": 0,
                    "net_cents": 0,
                    "charges_count": 0,
                    "refunds_count": 0,
                }

            # We only count charge + refund categories in “revenue”
            if cat in ("charge", "payment"):
                daily[day_key]["gross_cents"] += amount
                daily[day_key]["fees_cents"] += fee
                daily[day_key]["net_cents"] += net
                daily[day_key]["charges_count"] += 1

                total_gross += amount
                total_fees += fee
                total_net += net
                charges_count += 1

            elif cat in ("refund",):
                # refund amount is negative in Stripe; we store refunds as POSITIVE for display
                daily[day_key]["refunds_cents"] += abs(amount)
                daily[day_key]["fees_cents"] += fee       # fee may be 0 or negative (fee refunded)
                daily[day_key]["net_cents"] += net        # net should be negative
                daily[day_key]["refunds_count"] += 1

                total_refunds += abs(amount)
                total_fees += fee
                total_net += net
                refunds_count += 1

            else:
                ignored_categories[cat or "unknown"] = ignored_categories.get(cat or "unknown", 0) + 1

        currency_out = "MIXED" if len(currencies) > 1 else (next(iter(currencies)) if currencies else "USD")

        breakdown = []
        for _, v in sorted(daily.items()):
            breakdown.append({
                "date": v["date"],
                "gross": v["gross_cents"] / 100,
                "fees": v["fees_cents"] / 100,
                "refunds": v["refunds_cents"] / 100,
                "net": v["net_cents"] / 100,
                "charges_count": v["charges_count"],
                "refunds_count": v["refunds_count"],
            })

        days = (end_dt.date() - start_dt.date()).days + 1
        generated_at = datetime.now(timezone.utc).isoformat()

        return jsonify({
            "ok": True,
            "period": resolved_period,
            "currency": currency_out,
            "range": {
                "label": label,
                "start": start_dt.date().isoformat(),
                "end": end_dt.date().isoformat(),
                "timezone": REPORT_TZ_NAME,
                "days": days,
                "generated_at": generated_at,
            },
            "totals": {
                "gross": total_gross / 100,
                "fees": total_fees / 100,
                "refunds": total_refunds / 100,
                "net": total_net / 100,  # ✅ THIS IS “after Stripe fees”
                "charges_count": charges_count,
                "refunds_count": refunds_count,
            },
            "breakdown": breakdown,
            "meta": {
                "ignored_categories": ignored_categories,  # transparency if Stripe has disputes/payout rows in range
            }
        })

    except Exception as e:
        log.exception("Stripe revenue error")
        return _err(f"Stripe Error: {e}", 500)
