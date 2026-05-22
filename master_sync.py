import os
import stripe
from datetime import datetime, timezone
from core import sb_admin, STRIPE_SECRET_KEY

stripe.api_key = STRIPE_SECRET_KEY

def log_status(email, msg, level="INFO"):
    print(f"[{level}] {email:30} | {msg}")

def run_master_sync():
    print("\n🚀 --- STARTING MASTER SYNC ---")
    
    # Get all users with a Stripe ID
    users = sb_admin.table('user_profiles').select('user_id, stripe_customer_id, email').neq('stripe_customer_id', 'null').execute().data
    now_iso = datetime.now(timezone.utc).isoformat()

    for user in users:
        uid = user['user_id']
        email = user.get('email')

        # 1. CASH SHIELD: Skip users with active manual period
        cash_check = sb_admin.table('membership_periods') \
            .select('period_end') \
            .eq('owner_user_id', uid) \
            .eq('source', 'manual') \
            .gte('period_end', now_iso) \
            .execute().data
        
        if cash_check:
            log_status(email, "🛡️ SHIELDED (Active Cash ticket)")
            align_master_folder(uid)
            continue

        # 2. STRIPE SYNC
        try:
            subs = stripe.Subscription.list(customer=user['stripe_customer_id'], status='active', limit=1)
            found_sub = False
            for sub in subs.auto_paging_iter():
                found_sub = True
                price_id = sub['items']['data'][0]['price']['id']
                
                # Fetch Plan UUID
                plan_res = sb_admin.table('membership_plans').select('id').eq('stripe_price_id', price_id).execute().data
                if not plan_res: continue
                plan_uuid = plan_res[0]['id']
                
                # Update/Insert Membership Safely
                save_membership_safely(uid, sub, plan_uuid)
                create_period_if_missing(uid, sub, plan_uuid)
            
            if found_sub: log_status(email, "✅ SYNCED (Stripe)")
            else: log_status(email, "⚠️ SKIPPED (No Active Sub)")

        except Exception as e:
            log_status(email, f"❌ STRIPE ERROR: {str(e)[:40]}", "ERROR")

        # 3. ALIGN FOLDER
        align_master_folder(uid)

    print("🏁 --- SYNC COMPLETE ---\n")

def save_membership_safely(uid, sub, plan_uuid):
    # Check if membership exists for this user AND this plan
    existing = sb_admin.table('user_memberships') \
        .select('id') \
        .eq('owner_user_id', uid) \
        .eq('plan_id', plan_uuid) \
        .execute().data
    
    # Payload for updating (DO NOT include unique keys like owner_user_id/plan_id in update)
    update_data = {
        'status': 'active',
        'payment_provider': 'stripe',
        'provider_subscription_id': sub.id,
        'updated_at': datetime.now(timezone.utc).isoformat()
    }
    
    # Payload for inserting (MUST include unique keys)
    insert_data = {
        **update_data,
        'owner_user_id': uid,
        'subject_user_id': uid,
        'plan_id': plan_uuid
    }
    
    if existing:
        sb_admin.table('user_memberships').update(update_data).eq('id', existing[0]['id']).execute()
    else:
        sb_admin.table('user_memberships').insert(insert_data).execute()

def create_period_if_missing(uid, sub, plan_uuid):
    start = datetime.fromtimestamp(sub.current_period_start, tz=timezone.utc).isoformat()
    end = datetime.fromtimestamp(sub.current_period_end, tz=timezone.utc).isoformat()
    ref = f"{sub.id}:{sub.current_period_start}"
    
    if not sb_admin.table('membership_periods').select('id').eq('source_ref', ref).execute().data:
        mem = sb_admin.table('user_memberships').select('id').eq('owner_user_id', uid).eq('plan_id', plan_uuid).execute().data
        if mem:
            sb_admin.table('membership_periods').insert({
                'user_membership_id': mem[0]['id'],
                'owner_user_id': uid,
                'subject_user_id': uid,
                'plan_id': plan_uuid,
                'source': 'stripe',
                'source_ref': ref,
                'period_start': start,
                'period_end': end
            }).execute()

def align_master_folder(uid):
    latest = sb_admin.table('membership_periods') \
        .select('period_start, period_end, source') \
        .eq('owner_user_id', uid) \
        .eq('is_voided', False) \
        .order('period_end', desc=True) \
        .limit(1).execute().data
    
    if latest:
        ticket = latest[0]
        sb_admin.table('user_memberships').update({
            'current_period_start': ticket['period_start'],
            'current_period_end': ticket['period_end'],
            'payment_provider': ticket['source']
        }).eq('owner_user_id', uid).execute()

if __name__ == "__main__":
    run_master_sync()