import os
import stripe
from dotenv import load_dotenv
from datetime import datetime, timezone

# 1. Load Environment Variables
load_dotenv()
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

def get_stripe_only_report():
    print(f"\n📊 GENERATING STRIPE-ONLY REPORT...")
    print(f"   (Source: Direct Live Stripe Data)\n")

    # --- PART 1: SUBSCRIBER COUNTS ---
    print(f"{'='*40}")
    print(f" ACTIVE RECURRING SUBSCRIBERS")
    print(f"{'='*40}")

    # Fetch ALL subscriptions (Active & Past Due)
    # We expand 'data.plan.product' so we can get the actual Plan Name (e.g. "Gold Membership")
    subs = stripe.Subscription.list(
        limit=100, 
        status='all',
        expand=['data.plan.product'] 
    ).auto_paging_iter()

    active_count = 0
    past_due_count = 0
    canceled_count = 0
    
    plan_breakdown = {}

    for sub in subs:
        status = sub.status
        
        # 1. Count Statuses
        if status in ['active', 'trialing']:
            active_count += 1
            
            # Only count Plan Names for ACTIVE users
            product_name = "Unknown Plan"
            if sub.plan and sub.plan.product:
                # Handle case where product is an object vs string
                if isinstance(sub.plan.product, dict): # Expanded object
                    product_name = sub.plan.product.get('name', 'Unknown')
                elif hasattr(sub.plan.product, 'name'): # Class object
                    product_name = sub.plan.product.name
            
            plan_breakdown[product_name] = plan_breakdown.get(product_name, 0) + 1

        elif status in ['past_due', 'unpaid', 'incomplete']:
            past_due_count += 1
        elif status == 'canceled':
            canceled_count += 1

    print(f"✅ Active Subscribers:   {active_count}")
    print(f"⚠️ Past Due (Failed):    {past_due_count}")
    print(f"❌ Canceled (Total):     {canceled_count}")
    
    print("\n--- Active Plan Breakdown ---")
    for name, count in plan_breakdown.items():
        print(f"• {name:<25} {count}")

    # --- PART 2: REVENUE (THIS MONTH) ---
    print(f"\n{'='*40}")
    print(f" CASH COLLECTED ({datetime.now().strftime('%B %Y')})")
    print(f"{'='*40}")
    
    # Calculate start of month
    now = datetime.now(timezone.utc)
    start_of_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    start_ts = int(start_of_month.timestamp())

    txs = stripe.BalanceTransaction.list(
        created={'gte': start_ts},
        limit=100
    ).auto_paging_iter()

    gross = 0.0
    fees = 0.0
    net = 0.0
    count = 0

    for tx in txs:
        if tx.type in ['charge', 'payment']:
            gross += tx.amount
            fees += tx.fee
            net += tx.net
            count += 1
        elif tx.type == 'refund':
            gross -= abs(tx.amount)
            net += tx.net
            count += 1
    
    print(f"Total Transactions:      {count}")
    print(f"Gross Revenue:           ${gross/100:,.2f}  (Total Volume)")
    print(f"Stripe Fees:            -${fees/100:,.2f}")
    print(f"Net Revenue:             ${net/100:,.2f}   (Real Profit) 💰")

if __name__ == "__main__":
    get_stripe_only_report()