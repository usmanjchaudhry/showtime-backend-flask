import os
import stripe
from dotenv import load_dotenv
from supabase import create_client, Client

# --- CONFIGURATION ---
DRY_RUN = False  # <--- Back to False to try again
# ---------------------

load_dotenv()

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
SUPABASE_URL = os.environ["SUPABASE_URL"]
SERVICE_KEY = os.environ["SUPABASE_SERVICE_ROLE"]

sb_admin: Client = create_client(SUPABASE_URL, SERVICE_KEY)

def link_orphans():
    print(f"--- STARTING ORPHAN LINKER (Dry Run: {DRY_RUN}) ---\n")

    # 1. Fetch Linked IDs (to skip already linked ones)
    print("1. Loading existing links...")
    # Fetch plenty of rows to ensure we don't miss any
    response = sb_admin.table('user_memberships').select('provider_subscription_id', count='exact').execute()
    linked_ids = set()
    for row in response.data:
        if row.get('provider_subscription_id'):
            linked_ids.add(row['provider_subscription_id'])
            
    print(f"   Known linked IDs in DB: {len(linked_ids)}")

    # 2. Fetch Users (Email -> ID)
    print("2. Loading user directory...")
    users_response = sb_admin.auth.admin.list_users(per_page=1000)
    if hasattr(users_response, 'users'):
        user_list = users_response.users
    else:
        user_list = users_response
    
    db_users = {} 
    for u in user_list:
        if u.email:
            db_users[u.email.lower()] = u.id

    # 3. Scan & Link
    print("3. Scanning for potential links...")
    print(f"\n{'='*60}")
    
    subs = stripe.Subscription.list(
        limit=100, 
        status='all',
        expand=['data.customer'] 
    ).auto_paging_iter()

    linked_count = 0
    skipped_count = 0

    for sub in subs:
        if sub.id in linked_ids:
            continue 

        # Get Email
        stripe_email = None
        if sub.customer and hasattr(sub.customer, 'email') and sub.customer.email:
            stripe_email = sub.customer.email.lower()
        
        if not stripe_email or stripe_email not in db_users:
            skipped_count += 1
            continue

        # MATCH FOUND!
        user_id = db_users[stripe_email]
        
        # Determine status for DB
        if sub.status in ['active', 'trialing']:
            db_status = 'active'
        elif sub.status in ['past_due', 'unpaid']:
            db_status = 'past_due'
        else:
            db_status = 'canceled'

        print(f"🔗 Match Found: {stripe_email}")
        
        if not DRY_RUN:
            # FIX: Don't update blindly. Find the newest membership row first.
            mems_response = sb_admin.table('user_memberships') \
                .select('id, created_at') \
                .eq('owner_user_id', user_id) \
                .order('created_at', desc=True) \
                .execute()
            
            if not mems_response.data:
                 print("   ⚠️ Error: User exists in Auth, but has NO membership rows.")
                 continue

            # Pick the most recent one
            target_row_id = mems_response.data[0]['id']

            try:
                # Update specific row only
                sb_admin.table('user_memberships') \
                    .update({
                        'provider_subscription_id': sub.id,
                        'status': db_status
                    }) \
                    .eq('id', target_row_id) \
                    .execute()
                
                print("   ✅ Success: Linked to newest row.")
                linked_count += 1
            except Exception as e:
                print(f"   ❌ Failed to update: {e}")

        else:
            print("   [Dry Run] Would find newest membership row and update it.")
            linked_count += 1
            
        print("-" * 60)

    print(f"\n{'='*30}")
    print(f"LINKING COMPLETE (Dry Run: {DRY_RUN})")
    print(f"Matches Handled:    {linked_count}")
    print(f"Ghosts Skipped:     {skipped_count}")

if __name__ == "__main__":
    link_orphans()