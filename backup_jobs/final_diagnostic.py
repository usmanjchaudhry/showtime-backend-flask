import os
import stripe
from dotenv import load_dotenv
from supabase import create_client
from datetime import datetime, timezone

load_dotenv()
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
sb = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_SERVICE_ROLE"])

email = "bunkamajesty@gmail.com"
print(f"\n--- FINAL DIAGNOSTIC FOR: {email} ---")

user_res = sb.table("user_profiles").select("user_id, stripe_customer_id").eq("email", email).execute()
if not user_res.data:
    print("User not found!")
    exit()
    
uid = user_res.data[0]["user_id"]
customer_id = user_res.data[0]["stripe_customer_id"]

print(f"Stripe Customer ID: {customer_id}")

print("\n[ DATABASE PERIODS ]")
periods = sb.table("membership_periods").select("id, source_ref, period_start, period_end").eq("owner_user_id", uid).execute()
for p in periods.data:
    print(f"Ref: {p.get('source_ref')} | Start: {p['period_start'][:10]} | End: {p['period_end'][:10]}")

print("\n[ STRIPE API DATA ]")
subs = stripe.Subscription.list(customer=customer_id, status="all")
for sub in subs.data:
    print(f"\nSub ID: {sub.id}")
    print(f"Status: {sub.status}")
    start_dt = datetime.fromtimestamp(sub.current_period_start, tz=timezone.utc)
    end_dt = datetime.fromtimestamp(sub.current_period_end, tz=timezone.utc)
    print(f"API Period: {start_dt.strftime('%Y-%m-%d')} to {end_dt.strftime('%Y-%m-%d')}")
    
    expected_ref = f"{sub.id}:{sub.current_period_start}"
    print(f"Expected source_ref: {expected_ref}")

print("\n")