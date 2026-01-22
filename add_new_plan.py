import os
import stripe
from dotenv import load_dotenv
from supabase import create_client, Client
import re

# --- CONFIGURATION ---
# The NEW Price ID you are trying to add
NEW_PRICE_ID = "price_1Ss9H7LQmZaxf1vefUpTpPmH"
# ---------------------

load_dotenv()
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
SUPABASE_URL = os.environ["SUPABASE_URL"]
SERVICE_KEY = os.environ["SUPABASE_SERVICE_ROLE"]

sb_admin: Client = create_client(SUPABASE_URL, SERVICE_KEY)

def add_plan():
    print(f"--- IMPORTING NEW PLAN FROM STRIPE ---")
    print(f"Fetching details for: {NEW_PRICE_ID}...")

    try:
        # 1. Get Price & Product from Stripe
        price = stripe.Price.retrieve(NEW_PRICE_ID, expand=['product'])
        product = price.product

        # 2. Extract Data
        name = product.name
        slug_base = re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-')
        slug = f"{slug_base}-{price.recurring.interval}" 
        
        price_cents = price.unit_amount
        currency = price.currency.upper()
        interval = price.recurring.interval
        interval_count = price.recurring.interval_count

        print(f"   Name:     {name}")
        print(f"   Amount:   {price_cents} {currency}")
        print(f"   Interval: {interval_count} {interval}(s)")

        # 3. Insert into Supabase
        payload = {
            "name": name,
            "slug": slug,
            "description": product.description or "",
            "price_cents": price_cents,
            "currency": currency,
            "interval": interval,
            "interval_count": interval_count,
            "stripe_price_id": NEW_PRICE_ID,
            # "stripe_product_id": product.id,  <-- REMOVED THIS LINE (Not in your DB)
            "is_active": True,
            "stripe_checkout_mode": "subscription" 
        }

        data = sb_admin.table('membership_plans').insert(payload).execute()
        print(f"\n✅ SUCCESS! Plan added to database.")
        print(f"   Internal DB ID: {data.data[0]['id']}")

    except Exception as e:
        print(f"\n❌ ERROR: {e}")

if __name__ == "__main__":
    add_plan()