import os
import time
import stripe
from dotenv import load_dotenv
from supabase import create_client, Client
from datetime import datetime, timezone

# 1. Load Environment
load_dotenv()

# --- CONFIGURATION ---
DRY_RUN = False          # ✅ False = Keep syncing.
BATCH_SIZE = 100         
SLEEP_BETWEEN_BATCHES = 1
# ---------------------

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
SUPABASE_URL = os.environ["SUPABASE_URL"]
SERVICE_KEY = os.environ["SUPABASE_SERVICE_ROLE"]

sb_admin: Client = create_client(SUPABASE_URL, SERVICE_KEY)

def to_utc_ts(sec: int):
    if not sec: return "None"
    return datetime.fromtimestamp(int(sec), tz=timezone.utc)

def sync_user(user_id, customer_id, user_email):
    # 🛡️ BULLETPROOF CASH SHIELD 🛡️
    # Before we even ask Stripe, check the "Ticket Stubs" table.
    # Does this user have an active, unexpired Cash/Manual period?
    now_iso = datetime.now(timezone.utc).isoformat()
    cash_check = sb_admin.table('membership_periods') \
        .select('id, period_end') \
        .eq('owner_user_id', user_id) \
        .eq('source', 'manual') \
        .gte('period_end', now_iso) \
        .execute()
        
    if cash_check.data:
        # They have an active cash ticket in the future. DO NOT TOUCH THEM.
        print(f"   🛡️ [CASH SHIELD] {user_email} has active cash ticket until {cash_check.data[0]['period_end']}. Skipping Stripe sync.")
        return # This completely ejects them from the Stripe update process

    # --- If they are NOT shielded, proceed with normal Stripe Sync ---
    try:
        subs = stripe.Subscription.list(
            customer=customer_id,
            status='all',
            limit=100,
            expand=['data.items.data.price']
        )
    except Exception as e:
        if "test mode" not in str(e).lower():
            print(f"  ❌ Stripe Error for {user_email}: {e}")
        return

    for sub in subs.auto_paging_iter():
        sub_id = sub.get('id')
        status = sub.get('status', '')
        
        # Map Status
        db_status = 'active'
        if status in ['active', 'trialing']:
            db_status = 'active'
        elif status in ['past_due', 'unpaid', 'incomplete']:
            db_status = 'past_due'
        elif status in ['canceled', 'incomplete_expired']:
            db_status = 'canceled'
        
        if not sub.get('items') or not sub['items'].get('data'): 
            continue
            
        price = sub['items']['data'][0].get('price', {})
        price_id = price.get('id')
        if not price_id: continue
        
        plan_res = sb_admin.table('membership_plans').select('id, name').eq('stripe_price_id', price_id).execute()
        if not plan_res.data:
            continue
        plan_name = plan_res.data[0]['name']
        plan_uuid = plan_res.data[0]['id']

        # --- CHECK 1: STATUS SYNC ---
        current_mem = sb_admin.table('user_memberships').select('id, status, provider_subscription_id') \
            .eq('owner_user_id', user_id) \
            .eq('plan_id', plan_uuid) \
            .limit(1) \
            .execute()
        
        if current_mem.data:
            existing_mem_id = current_mem.data[0]['id']
            current_status = current_mem.data[0]['status']
            current_sub_id = current_mem.data[0]['provider_subscription_id']

            if current_status != db_status or current_sub_id != sub_id:
                print(f"   🚩 [MISMATCH] {user_email} | {plan_name}")
                print(f"      - DB: {current_status} -> Stripe: {db_status}")
                
                if not DRY_RUN:
                    try:
                        update_payload = {
                            'status': db_status, 
                            'provider_subscription_id': sub_id,
                            'payment_provider': 'stripe',
                            'updated_at': datetime.now(timezone.utc).isoformat()
                        }
                        sb_admin.table('user_memberships').update(update_payload).eq('id', existing_mem_id).execute()
                        print(f"      ✅ Fixed DB status (Updated existing row).")
                    except Exception as e:
                        print(f"      ❌ Update Failed: {e}")
            else:
                print(f"   ✅ [OK] {user_email} is synced ({db_status})")
                        
        else:
            print(f"   🚩 [MISSING] {user_email} | {plan_name}")
            print(f"      - DB: DOES NOT EXIST -> Stripe: {db_status}")
            
            if not DRY_RUN:
                insert_payload = {
                    'owner_user_id': user_id,
                    'subject_user_id': user_id,
                    'plan_id': plan_uuid,
                    'provider_customer_id': customer_id,
                    'provider_subscription_id': sub_id,
                    'status': db_status,
                    'payment_provider': 'stripe',
                    'updated_at': datetime.now(timezone.utc).isoformat()
                }
                try:
                    sb_admin.table('user_memberships').insert(insert_payload).execute()
                    print(f"      ✅ Fixed DB status (Inserted new row).")
                except Exception as e:
                    print(f"      ❌ Insert Failed: {e}")

        # --- CHECK 2: ACCESS PERIODS ---
        if db_status == 'active':
            start_ts = sub.get('current_period_start')
            end_ts = sub.get('current_period_end')
            
            if not start_ts or not end_ts:
                try:
                    invoices = stripe.Invoice.list(subscription=sub_id, limit=1)
                    if invoices.data and invoices.data[0].get("lines") and invoices.data[0]["lines"].get("data"):
                        period = invoices.data[0]["lines"]["data"][0].get("period", {})
                        start_ts = period.get("start")
                        end_ts = period.get("end")
                except Exception as e:
                    print(f"      ⚠️ Could not fetch invoice fallback for {user_email}: {e}")
            
            if start_ts and end_ts:
                source_ref = f"{sub_id}:{start_ts}"
                check = sb_admin.table('membership_periods').select('id').eq('source_ref', source_ref).execute()
                
                if not check.data:
                    print(f"      📅 [MISSING PERIOD] {to_utc_ts(start_ts)} -> {to_utc_ts(end_ts)}")
                    if not DRY_RUN:
                        mem_res = sb_admin.table('user_memberships').select('id').eq('provider_subscription_id', sub_id).execute()
                        if not mem_res.data:
                            mem_res = sb_admin.table("user_memberships").select("id").eq("owner_user_id", user_id).eq("status", "active").execute()
                            
                        if mem_res.data:
                            mem_id = mem_res.data[0]['id']
                            try:
                                sb_admin.table('membership_periods').insert({
                                    'user_membership_id': mem_id,
                                    'owner_user_id': user_id,
                                    'subject_user_id': user_id,
                                    'plan_id': plan_uuid,
                                    'source': 'stripe',
                                    'source_ref': source_ref,
                                    'period_start': to_utc_ts(start_ts).isoformat(),
                                    'period_end': to_utc_ts(end_ts).isoformat()
                                }).execute()
                                
                                sb_admin.table('user_memberships').update({
                                    "current_period_start": to_utc_ts(start_ts).isoformat(),
                                    "current_period_end": to_utc_ts(end_ts).isoformat()
                                }).eq("id", mem_id).execute()
                                
                                print(f"      ✅ Inserted missing period.")
                            except Exception as e:
                                print(f"      ❌ DB Error inserting period: {e}")

def run_cron():
    print(f"--- STARTING SYNC (Dry Run: {DRY_RUN}) ---")
    
    users = sb_admin.table('user_profiles') \
        .select('user_id, stripe_customer_id, email') \
        .neq('stripe_customer_id', 'null') \
        .execute()
    
    all_users = users.data
    total = len(all_users)
    print(f"Checking {total} users...\n")

    count = 0
    for user in all_users:
        count += 1
        sync_user(user['user_id'], user['stripe_customer_id'], user.get('email'))
        
        if count % BATCH_SIZE == 0:
            time.sleep(SLEEP_BETWEEN_BATCHES)

    print("\n--- CHECK COMPLETE ---")

if __name__ == "__main__":
    run_cron()