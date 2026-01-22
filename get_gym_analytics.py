import os
import stripe
from dotenv import load_dotenv
from supabase import create_client, Client
from datetime import datetime, timezone

# 1. Load Environment Variables
load_dotenv()

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
SUPABASE_URL = os.environ["SUPABASE_URL"]
SERVICE_KEY = os.environ["SUPABASE_SERVICE_ROLE"]

sb_admin: Client = create_client(SUPABASE_URL, SERVICE_KEY)

def print_header(title):
    print(f"\n{'='*40}")
    print(f" {title}")
    print(f"{'='*40}")

def get_gym_analytics():
    print("\n📊 GENERATING ANALYTICS REPORT...")
    
    # --- PART 1: USER METRICS (Source: Supabase) ---
    print_header("USER METRICS")

    # A. Total Signups (Everyone in the database)
    # count='exact' gives us the number without fetching all the data rows
    response = sb_admin.table('user_profiles').select('*', count='exact', head=True).execute()
    total_signups = response.count
    print(f"Total Signups (All Time):   {total_signups}")

    # B. Active Members (People with 'active' or 'trialing' status)
    response = sb_admin.table('user_memberships') \
        .select('*', count='exact', head=True) \
        .in_('status', ['active', 'trialing']) \
        .execute()
    active_members = response.count
    print(f"Active Paying Members:      {active_members}")

    # C. At Risk (Past Due)
    response = sb_admin.table('user_memberships') \
        .select('*', count='exact', head=True) \
        .eq('status', 'past_due') \
        .execute()
    past_due = response.count
    print(f"Past Due (Payment Failed):  {past_due} ⚠️")

    # --- PART 2: PLAN BREAKDOWN (Source: Supabase) ---
    print_header("MEMBERSHIP BREAKDOWN")
    
    # Fetch all active memberships to group them
    mems = sb_admin.table('user_memberships') \
        .select('plan_id, status') \
        .eq('status', 'active') \
        .execute()
    
    # Fetch plan names
    plans = sb_admin.table('membership_plans').select('id, name').execute()
    plan_map = {p['id']: p['name'] for p in plans.data}

    # Count them up
    counts = {}
    for m in mems.data:
        p_name = plan_map.get(m['plan_id'], 'Unknown Plan')
        counts[p_name] = counts.get(p_name, 0) + 1
    
    for name, count in counts.items():
        print(f"• {name:<25} {count}")

    # --- PART 3: FINANCIALS (Source: Stripe) ---
    # We calculate revenue for the CURRENT MONTH (e.g., Jan 1st to Now)
    print_header(f"FINANCIALS ({datetime.now().strftime('%B %Y')})")
    
    # Calculate start of month timestamp
    now = datetime.now(timezone.utc)
    start_of_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    start_ts = int(start_of_month.timestamp())

    print("Calculating Cash Flow... (Scanning Stripe Transactions)")
    
    # Fetch balance transactions (Real money movement)
    txs = stripe.BalanceTransaction.list(
        created={'gte': start_ts},
        limit=100
    ).auto_paging_iter()

    gross = 0.0
    fees = 0.0
    net = 0.0
    tx_count = 0

    for tx in txs:
        if tx.type in ['charge', 'payment']:
            gross += tx.amount
            fees += tx.fee
            net += tx.net
            tx_count += 1
        elif tx.type == 'refund':
            gross -= abs(tx.amount)
            net += tx.net
            tx_count += 1
    
    # Convert cents to dollars
    print(f"Transactions Count:     {tx_count}")
    print(f"Gross Revenue:          ${gross/100:,.2f}  (Total Charged)")
    print(f"Stripe Fees:           -${fees/100:,.2f}")
    print(f"Net Revenue:            ${net/100:,.2f}   (Hit the Bank) 💰")

if __name__ == "__main__":
    get_gym_analytics()