import os
import stripe
from dotenv import load_dotenv
from supabase import create_client, Client

# --- CONFIGURATION ---
DRY_RUN = False  # <--- Set to False to apply fixes
# ---------------------

load_dotenv()

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
SUPABASE_URL = os.environ["SUPABASE_URL"]
SERVICE_KEY = os.environ["SUPABASE_SERVICE_ROLE"]

sb_admin: Client = create_client(SUPABASE_URL, SERVICE_KEY)

def score_status(status):
    """Helper to prioritize memberships: Active > Past Due > Canceled"""
    if status in ['active', 'trialing']: return 3
    if status in ['past_due', 'unpaid']: return 2
    return 1

def create_missing_memberships():
    print(f"--- CREATING MISSING MEMBERSHIPS (Dry Run: {DRY_RUN}) ---\n")

    # 1. Fetch Users
    print("1. Loading user directory...")
    users_response = sb_admin.auth.admin.list_users(per_page=1000)
    user_list = users_response.users if hasattr(users_response, 'users') else users_response
    
    db_users = {} 
    for u in user_list:
        if u.email:
            db_users[u.email.lower()] = u.id

    # 2. Scan & Group Subscriptions
    print("2. Scanning Stripe and selecting BEST subscription per user...")
    
    subs = stripe.Subscription.list(
        limit=100, 
        status='all',
        expand=['data.customer'] 
    ).auto_paging_iter()

    # Map: email -> Best Subscription Object
    best_subs = {}

    for sub in subs:
        stripe_email = None
        if sub.customer and hasattr(sub.customer, 'email') and sub.customer.email:
            stripe_email = sub.customer.email.lower()
        
        if not stripe_email or stripe_email not in db_users:
            continue

        # Logic: Keep the "Highest Scoring" subscription for this email
        current_best = best_subs.get(stripe_email)
        if not current_best:
            best_subs[stripe_email] = sub
        else:
            if score_status(sub.status) > score_status(current_best.status):
                best_subs[stripe_email] = sub
                # (If equal, we stick with the first one found, or could check dates)

    # 3. Create Rows
    print(f"   Found {len(best_subs)} users with Stripe subscriptions.")
    created_count = 0

    for email, sub in best_subs.items():
        user_id = db_users[email]

        # CHECK: Does this user already have a membership?
        check = sb_admin.table('user_memberships').select('id').eq('owner_user_id', user_id).execute()
        
        if check.data:
            continue # They are fine, skip them.

        # IF HERE: User has NO membership row. We create one using their BEST subscription.
        db_status = sub.status
        if db_status == 'trialing': db_status = 'active'
        if db_status == 'unpaid': db_status = 'past_due'
        
        print(f"🔧 Fixing: {email} -> Creating {db_status.upper()} row (Sub: {sub.id})")

        if not DRY_RUN:
            try:
                sb_admin.table('user_memberships').insert({
                    'owner_user_id': user_id,
                    'subject_user_id': user_id, 
                    'status': db_status,
                    'provider_subscription_id': sub.id,
                    'payment_provider': 'stripe',
                    'plan_id': '1b4e6ef9-7b7e-4435-be13-df24001ee6ea' # Generic Plan ID
                }).execute()
                print("   ✅ Created!")
                created_count += 1
            except Exception as e:
                print(f"   ❌ Failed: {e}")
        else:
            print(f"   [Dry Run] Would insert row.")
            created_count += 1

    print(f"\nTotal Memberships Created: {created_count}")

if __name__ == "__main__":
    create_missing_memberships()