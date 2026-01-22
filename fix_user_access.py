import os
import stripe
from dotenv import load_dotenv
from supabase import create_client, Client
from datetime import datetime, timezone

# --- CONFIGURATION ---
DRY_RUN = False  # <--- LIVE MODE ACTIVATED
# ---------------------

load_dotenv()

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
SUPABASE_URL = os.environ["SUPABASE_URL"]
SERVICE_KEY = os.environ["SUPABASE_SERVICE_ROLE"]

sb_admin: Client = create_client(SUPABASE_URL, SERVICE_KEY)

def fix_user_access():
    print(f"--- STARTING ACCESS CHECK (Dry Run: {DRY_RUN}) ---")
    
    subscriptions = stripe.Subscription.list(
        limit=100, 
        status='all' 
    ).auto_paging_iter()

    stats = {'scanned': 0, 'to_fix': 0, 'to_update_status': 0}

    for sub in subscriptions:
        try:
            # USE getattr() - The safest way to read Stripe Objects
            stripe_id = sub.id
            stripe_status = sub.status
            
            # 1. Determine correct status
            if stripe_status in ['active', 'trialing']:
                should_have_access = True
                target_status = 'active'
            elif stripe_status in ['past_due', 'unpaid', 'incomplete']:
                should_have_access = False
                target_status = 'past_due'
            else:
                should_have_access = False
                target_status = 'canceled'

            # 2. Check DB Status
            response = sb_admin.table('user_memberships') \
                .select('id, status, plan_id, owner_user_id, subject_user_id, dependent_id') \
                .eq('provider_subscription_id', stripe_id) \
                .execute()

            if not response.data:
                continue # Orphan

            membership = response.data[0]
            current_db_status = membership['status']
            stats['scanned'] += 1

            # --- CHECK 1: Status Mismatch? ---
            if current_db_status != target_status:
                print(f"📝 {stripe_id}: Status mismatch (DB: {current_db_status} -> Stripe: {target_status})")
                if not DRY_RUN:
                    sb_admin.table('user_memberships').update({'status': target_status}).eq('id', membership['id']).execute()
                stats['to_update_status'] += 1

            # --- CHECK 2: Missing Access Period? ---
            if should_have_access:
                # --- STRATEGY A: Top-level attributes ---
                start_ts = getattr(sub, 'current_period_start', None)
                end_ts = getattr(sub, 'current_period_end', None)

                # --- STRATEGY B: Check 'items' safely ---
                if (not start_ts or not end_ts):
                    try:
                        items_obj = sub.get('items')
                        if items_obj and hasattr(items_obj, 'data') and len(items_obj.data) > 0:
                            first_item = items_obj.data[0]
                            start_ts = getattr(first_item, 'current_period_start', None)
                            end_ts = getattr(first_item, 'current_period_end', None)
                    except Exception:
                        pass

                # --- STRATEGY C: Fallback to Created Date ---
                if not start_ts and sub.created:
                    start_ts = sub.created

                if not start_ts or not end_ts:
                    print(f"⚠️ {stripe_id}: CRITICAL - Dates still missing. Skipping.")
                    continue

                source_ref = f"{stripe_id}:{start_ts}"

                existing = sb_admin.table('membership_periods') \
                    .select('id') \
                    .eq('source_ref', source_ref) \
                    .execute()

                if not existing.data:
                    end_date_str = datetime.fromtimestamp(end_ts).strftime('%Y-%m-%d')
                    print(f"🚨 {stripe_id}: MISSING ACCESS! (Paid thru {end_date_str})")
                    
                    if not DRY_RUN:
                        period_start = datetime.fromtimestamp(start_ts, timezone.utc).isoformat()
                        period_end = datetime.fromtimestamp(end_ts, timezone.utc).isoformat()
                        
                        sb_admin.table('membership_periods').insert({
                            'user_membership_id': membership['id'],
                            'owner_user_id': membership['owner_user_id'],
                            'plan_id': membership['plan_id'],
                            'source': 'stripe',
                            'source_ref': source_ref,
                            'period_start': period_start,
                            'period_end': period_end,
                            'subject_user_id': membership.get('subject_user_id'),
                            'dependent_id': membership.get('dependent_id')
                        }).execute()
                        print("   ✅ Fixed: Access Granted.")
                    else:
                        print("   [Dry Run] Would insert access period.")
                    
                    stats['to_fix'] += 1

        except Exception as e:
            print(f"❌ Error scanning {sub.id}: {e}")

    print("\n" + "="*30)
    print(f"REPORT COMPLETE (Dry Run: {DRY_RUN})")
    print(f"Scanned: {stats['scanned']}")
    print(f"Status Updates Needed: {stats['to_update_status']}")
    print(f"Missing Access Found:  {stats['to_fix']}")

if __name__ == "__main__":
    fix_user_access()