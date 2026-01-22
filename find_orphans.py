import os
import stripe
from dotenv import load_dotenv
from supabase import create_client, Client

load_dotenv()

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
SUPABASE_URL = os.environ["SUPABASE_URL"]
SERVICE_KEY = os.environ["SUPABASE_SERVICE_ROLE"]

# Initialize Supabase Admin
sb_admin: Client = create_client(SUPABASE_URL, SERVICE_KEY)

def find_orphans():
    print(f"--- STARTING ORPHAN SCAN ---\n")

    # 1. Get ALL linked Subscription IDs from Database
    print("1. Fetching linked subscriptions from Supabase...")
    response = sb_admin.table('user_memberships').select('provider_subscription_id').execute()
    linked_ids = set()
    for row in response.data:
        if row.get('provider_subscription_id'):
            linked_ids.add(row['provider_subscription_id'])
    
    print(f"   Found {len(linked_ids)} linked subscriptions in DB.")

    # 2. Get ALL Users from Database (Email + ID)
    print("2. Fetching all users from Supabase Auth...")
    
    # FIX: Pass arguments directly, not inside 'params'
    # Fetching first 1000 users (should cover everyone for now)
    users_response = sb_admin.auth.admin.list_users(per_page=1000)
    
    # The response object structure depends on version, handling both:
    if hasattr(users_response, 'users'):
        user_list = users_response.users
    else:
        user_list = users_response # In some versions it returns the list directly
    
    db_users = {} # Map: email -> user_id
    for u in user_list:
        if u.email:
            db_users[u.email.lower()] = u.id
    
    print(f"   Found {len(db_users)} registered users in DB.")

    # 3. Scan Stripe for Orphans
    print("3. Scanning Stripe for unlinked subscriptions...")
    print(f"\n{'='*60}")
    print(f" {'ORPHAN REPORT':<40} | {'STATUS'}")
    print(f"{'='*60}")

    subs = stripe.Subscription.list(
        limit=100, 
        status='all',
        expand=['data.customer'] 
    ).auto_paging_iter()

    orphan_count = 0
    match_count = 0
    ghost_count = 0

    for sub in subs:
        # Check if this Stripe Sub is already in our DB
        if sub.id in linked_ids:
            continue # It's linked, skip it.

        orphan_count += 1
        
        # Get details
        stripe_email = "Unknown"
        if sub.customer and hasattr(sub.customer, 'email') and sub.customer.email:
            stripe_email = sub.customer.email.lower()
        
        # Try to find a plan name
        plan_name = "Unknown Plan"
        try:
            if hasattr(sub, 'plan') and sub.plan:
                if hasattr(sub.plan, 'nickname') and sub.plan.nickname:
                    plan_name = sub.plan.nickname
                elif hasattr(sub.plan, 'product'):
                     # If product is expanded or just an ID, we skip complex fetching for speed
                     pass
        except:
            pass

        # COMPARISON: Does this email exist in Supabase?
        is_match = stripe_email in db_users
        
        status_icon = "✅ MATCH FOUND" if is_match else "❌ NO USER IN DB"
        if is_match:
            match_count += 1
        else:
            ghost_count += 1

        print(f"Stripe ID: {sub.id} ({sub.status})")
        print(f"Email:     {stripe_email}")
        print(f"Plan:      {plan_name}")
        print(f"Result:    {status_icon}")
        if is_match:
            print(f"Action:    Ready to Link -> User ID: {db_users[stripe_email]}")
        else:
            print(f"Action:    User needs to sign up.")
        print("-" * 60)

    print(f"\nSUMMARY:")
    print(f"Total Orphans Found: {orphan_count}")
    print(f"Matches (Fixable):   {match_count} (We can link these now)")
    print(f"Ghosts (No Account): {ghost_count} (Coaches or Manual users)")

if __name__ == "__main__":
    find_orphans()