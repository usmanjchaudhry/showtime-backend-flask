import os
import stripe
from dotenv import load_dotenv
from supabase import create_client, Client

# 1. Load environment variables from your .env file
load_dotenv()

# --- CONFIGURATION (EDIT THESE) ---
# The OLD Price ID (the one people are currently subscribed to)
OLD_STRIPE_PRICE_ID = 'price_1S1EG4LQmZaxf1vep5N1iY0x' 

# The NEW Price ID (the one you just created in Stripe Dashboard)
NEW_STRIPE_PRICE_ID = 'price_1Ss9H7LQmZaxf1vefUpTpPmH' 

# ----------------------------------

# 2. Setup Stripe
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

# 3. Setup Supabase (Using Service Role to bypass RLS, just like your app.py)
SUPABASE_URL = os.environ["SUPABASE_URL"]
# Your app.py uses "SUPABASE_SERVICE_ROLE", so we use that here too
SERVICE_KEY = os.environ["SUPABASE_SERVICE_ROLE"] 

sb_admin: Client = create_client(
    SUPABASE_URL,
    SERVICE_KEY,
)

def migrate_gym_members():
    print(f"--- STARTING MIGRATION ---")
    print(f"Moving active subs from {OLD_STRIPE_PRICE_ID} -> {NEW_STRIPE_PRICE_ID}")

    # A. Get the internal UUID for the NEW plan from your database
    # We need this to update the 'user_memberships' table so it points to the right plan locally
    print("Looking up new plan in Supabase...")
    response = sb_admin.table('membership_plans') \
        .select('id, name') \
        .eq('stripe_price_id', NEW_STRIPE_PRICE_ID) \
        .execute()
    
    if not response.data:
        print(f"❌ ERROR: Could not find a plan in Supabase with stripe_price_id: {NEW_STRIPE_PRICE_ID}")
        print("Did you insert the new plan row into the 'membership_plans' table yet?")
        return
        
    new_internal_plan_uuid = response.data[0]['id']
    new_plan_name = response.data[0]['name']
    print(f"✅ Found Plan: {new_plan_name} ({new_internal_plan_uuid})")

    # B. Iterate through Stripe Subscriptions
    # auto_paging_iter handles fetching 1000s of users if necessary
    print("Fetching subscriptions from Stripe...")
    subscriptions = stripe.Subscription.list(
        price=OLD_STRIPE_PRICE_ID, 
        status='active', 
        limit=100
    ).auto_paging_iter()

    count = 0
    errors = 0

    for sub in subscriptions:
        try:
            print(f"Migrating {sub.id} (Customer: {sub.customer})... ", end='')

            # 1. Update Stripe
            # Gym memberships usually have 1 item. We get that item's ID.
            item_id = sub['items']['data'][0].id
            
            stripe.Subscription.modify(
                sub.id,
                items=[{
                    'id': item_id,
                    'price': NEW_STRIPE_PRICE_ID,
                }],
                # 'none' ensures they aren't charged the difference immediately.
                # The new price applies starting next billing cycle.
                proration_behavior='none', 
            )

            # 2. Update Supabase (Directly, to keep it in sync without waiting for webhook)
            sb_admin.table('user_memberships') \
                .update({
                    'plan_id': new_internal_plan_uuid,
                    'updated_at': 'now()'
                }) \
                .eq('provider_subscription_id', sub.id) \
                .execute()

            print("✅ Done")
            count += 1

        except Exception as e:
            print(f"❌ FAILED: {e}")
            errors += 1

    print("-" * 30)
    print(f"Migration Complete.")
    print(f"Success: {count}")
    print(f"Errors:  {errors}")

if __name__ == "__main__":
    # Safety confirmation
    confirm = input(f"Are you sure you want to migrate users to {NEW_STRIPE_PRICE_ID}? (yes/no): ")
    if confirm.lower() == "yes":
        migrate_gym_members()
    else:
        print("Cancelled.")