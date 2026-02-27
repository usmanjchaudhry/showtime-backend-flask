import os
from dotenv import load_dotenv
from supabase import create_client

# Load passwords
load_dotenv()
sb = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_SERVICE_ROLE"])

email = "bunkamajesty@gmail.com"

print(f"\n🔍 DEBUGGING USER: {email}")
user_res = sb.table("user_profiles").select("user_id").eq("email", email).execute()

if not user_res.data:
    print("User not found in profiles!")
    exit()

uid = user_res.data[0]["user_id"]

print("\n--- 1. MEMBERSHIP STATUS ---")
mems = sb.table("user_memberships").select("id, status, plan_id, dependent_id").eq("owner_user_id", uid).execute()
for m in mems.data:
    print(f"ID: {m['id']} | Status: {m['status']} | Dependent: {m.get('dependent_id')}")

print("\n--- 2. ACCESS PERIODS (The Calendar) ---")
periods = sb.table("membership_periods").select("id, period_start, period_end, is_voided, subject_user_id, dependent_id").eq("owner_user_id", uid).execute()
for p in periods.data:
    print(f"Start: {p['period_start']} | End: {p['period_end']} | Voided: {p['is_voided']} | Subj: {p.get('subject_user_id')} | Dep: {p.get('dependent_id')}")
print("\n")