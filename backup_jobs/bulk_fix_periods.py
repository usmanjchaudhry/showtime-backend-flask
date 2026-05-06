import os
import stripe
from dotenv import load_dotenv
from supabase import create_client
from datetime import datetime, timezone

# Load passwords
load_dotenv()
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
sb = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_SERVICE_ROLE"])

print("\n🚀 STARTING BULK FIX FOR ALL USERS...")

# 1. Get all users with Stripe IDs
users_res = sb.table("user_profiles").select("user_id, email, stripe_customer_id").neq("stripe_customer_id", "null").execute()
users = users_res.data
print(f"Found {len(users)} users connected to Stripe.\n")

fixed_count = 0
error_count = 0

for user in users:
    uid = user["user_id"]
    email = user.get("email", "Unknown")
    customer_id = user["stripe_customer_id"]
    
    try:
        # 2. Get only ACTIVE Stripe Subscriptions
        subs = stripe.Subscription.list(customer=customer_id, status="active")
        
        for sub in subs.data:
            # ✅ FIXED: Use .get() to pull the data correctly
            start_ts = sub.get("current_period_start")
            end_ts = sub.get("current_period_end")
            sub_id = sub.get("id")
            
            if not start_ts or not end_ts:
                continue
                
            start_dt = datetime.fromtimestamp(start_ts, tz=timezone.utc)
            end_dt = datetime.fromtimestamp(end_ts, tz=timezone.utc)
            
            source_ref = f"{sub_id}:{start_ts}"
            
            # 3. Check if this exact time window exists in the database
            check = sb.table("membership_periods").select("id").eq("source_ref", source_ref).execute()
            
            if not check.data:
                # Missing! Let's find the matching DB membership to link it to
                mem_res = sb.table("user_memberships").select("id, plan_id").eq("provider_subscription_id", sub_id).execute()
                
                if not mem_res.data:
                    continue
                    
                mem_id = mem_res.data[0]["id"]
                plan_id = mem_res.data[0]["plan_id"]
                
                print(f"🔧 Fixing [{email}] - Missing period: {start_dt.strftime('%Y-%m-%d')} to {end_dt.strftime('%Y-%m-%d')}")
                
                try:
                    # 4. FORCE INSERT THE MISSING DATES
                    sb.table("membership_periods").insert({
                        "user_membership_id": mem_id,
                        "owner_user_id": uid,
                        "subject_user_id": uid,
                        "plan_id": plan_id,
                        "source": "stripe",
                        "source_ref": source_ref,
                        "period_start": start_dt.isoformat(),
                        "period_end": end_dt.isoformat()
                    }).execute()
                    print("   ✅ Successfully inserted. User can now access the gym.")
                    fixed_count += 1
                except Exception as e:
                    print(f"   ❌ DB ERROR inserting for {email}:")
                    print(f"      {e}")
                    error_count += 1
                    
    except Exception as e:
        # Silently skip the test-mode account error to keep the output clean
        if "test mode" not in str(e):
            print(f"❌ STRIPE ERROR for {email}: {e}")

print(f"\n🎉 BULK FIX COMPLETE!")
print(f"Fixed {fixed_count} missing periods.")
print(f"Errors encountered: {error_count}\n")