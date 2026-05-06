import os
import stripe
from dotenv import load_dotenv
from supabase import create_client, Client
import re

# --- CONFIGURATION ---
NEW_PRICE_ID = "price_1SsTHDLQmZaxf1veZBMwv6Na"
# ---------------------

load_dotenv()
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
SUPABASE_URL = os.environ["SUPABASE_URL"]
SERVICE_KEY = os.environ["SUPABASE_SERVICE_ROLE"]

sb_admin: Client = create_client(SUPABASE_URL, SERVICE_KEY)

def add_plan():
    print(f"--- IMPORTING PLAN FROM STRIPE ---")
    print(f"Fetching details for: {NEW_PRICE_ID}...")

    try:
        # 1. Get Price & Product
        price = stripe.Price.retrieve(NEW_PRICE_ID, expand=['product'])
        product = price.product
        
        name = product.name
        price_cents = price.unit_amount
        currency = price.currency.upper()

        # 2. Detect Mode (Subscription vs One-Time)
        if price.recurring:
            print("   👉 Detected Type: RECURRING SUBSCRIPTION")
            mode = "subscription"
            interval = price.recurring.interval
            interval_count = price.recurring.interval_count
            slug_suffix = f"{interval}"
        else:
            print("   👉 Detected Type: ONE-TIME PAYMENT")
            mode = "payment"
            
            # For one-time payments, Stripe doesn't know how long access lasts.
            # We must ask YOU.
            print("\n   ⚠️  How long should this pass grant access?")
            print("      (e.g., for a Day Pass, enter 'day' and '1')")
            
            valid_intervals = ['day', 'week', 'month', 'year']
            interval = input(f"   - Interval ({'/'.join(valid_intervals)}): ").strip().lower()
            while interval not in valid_intervals:
                interval = input(f"     Invalid. Choose {valid_intervals}: ").strip().lower()
                
            interval_count = input("   - Count (e.g. 1): ").strip()
            if not interval_count: interval_count = 1
            else: interval_count = int(interval_count)
            
            slug_suffix = "pass"

        # Create slug
        slug_base = re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-')
        slug = f"{slug_base}-{slug_suffix}"

        print(f"\n   --- Summary ---")
        print(f"   Name:     {name}")
        print(f"   Amount:   {price_cents} {currency}")
        print(f"   Access:   {interval_count} {interval}(s)")
        print(f"   Mode:     {mode}")
        print(f"   Slug:     {slug}")

        # 3. Check for duplicates
        check = sb_admin.table('membership_plans').select('*').eq('stripe_price_id', NEW_PRICE_ID).execute()
        if check.data:
            print("\n⚠️  This plan is ALREADY in your database!")
            return

        # 4. Insert
        confirm = input("\nAdd this to database? (y/n): ")
        if confirm.lower() != 'y':
            print("Cancelled.")
            return

        payload = {
            "name": name,
            "slug": slug,
            "description": product.description or "",
            "price_cents": price_cents,
            "currency": currency,
            "interval": interval,
            "interval_count": interval_count,
            "stripe_price_id": NEW_PRICE_ID,
            "is_active": True,
            "stripe_checkout_mode": mode 
        }

        data = sb_admin.table('membership_plans').insert(payload).execute()
        print(f"\n✅ SUCCESS! Plan added.")
        print(f"   Internal DB ID: {data.data[0]['id']}")

    except Exception as e:
        print(f"\n❌ ERROR: {e}")

if __name__ == "__main__":
    add_plan()