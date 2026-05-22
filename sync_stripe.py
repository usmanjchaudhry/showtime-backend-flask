import os
import stripe
from core import sb_admin, STRIPE_SECRET_KEY, log

# ==========================================
# 🛑 SET THIS TO FALSE TO ACTUALLY MAKE CHANGES
# ==========================================
DRY_RUN = False

def run_sync():
    if DRY_RUN:
        log.info("🚀 STARTING DRY RUN - ONLY LINKING EXISTING ACCOUNTS")
    else:
        log.info("Starting LIVE Stripe customer sync (Link-Only)...")
    
    if not STRIPE_SECRET_KEY:
        log.error("STRIPE_SECRET_KEY is missing. Aborting.")
        return

    stripe.api_key = STRIPE_SECRET_KEY

    # 1. Get all users who DO NOT have a Stripe Customer ID yet
    response = sb_admin.table("user_profiles").select("user_id, email").is_("stripe_customer_id", "null").execute()
    users = response.data

    if not users:
        log.info("All users have a Stripe ID. Nothing to do.")
        return

    log.info(f"Checking {len(users)} users against Stripe records...")
    
    linked_count = 0

    for u in users:
        email = (u.get("email") or "").strip()
        user_id = u.get("user_id")
        
        if not email:
            continue

        try:
            # 2. Search Stripe to see if they already exist
            customers = stripe.Customer.search(
                query=f"email:'{email}'",
                limit=1
            )
            
            if customers and customers.data:
                # 3. They exist! Link them.
                stripe_id = customers.data[0].id
                
                if DRY_RUN:
                    log.info(f"[DRY RUN] Would LINK existing Stripe customer {stripe_id} to {email}")
                else:
                    log.info(f"Linking Stripe customer {stripe_id} to {email}...")
                    sb_admin.table("user_profiles").update({"stripe_customer_id": stripe_id}).eq("user_id", user_id).execute()
                
                linked_count += 1

        except Exception as e:
            log.error(f"Failed to process user {email}: {e}")

    if DRY_RUN:
        log.info(f"🏁 DRY RUN COMPLETE - Would have linked {linked_count} users.")
    else:
        log.info(f"🏁 SYNC COMPLETE - Successfully linked {linked_count} users.")

if __name__ == "__main__":
    run_sync()