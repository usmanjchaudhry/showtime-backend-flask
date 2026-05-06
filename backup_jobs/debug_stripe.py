import os
import stripe
from dotenv import load_dotenv
from datetime import datetime, timezone

load_dotenv()
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

email = "bunkamajesty@gmail.com"
print(f"\n🔍 CHECKING STRIPE FOR: {email}")

customers = stripe.Customer.list(email=email)
if not customers.data:
    print("User not found in Stripe!")
else:
    for cus in customers.data:
        print(f"\nFound Customer: {cus.id}")
        subs = stripe.Subscription.list(customer=cus.id, status="all")
        
        if not subs.data:
            print("No subscriptions found.")
            
        for sub in subs.data:
            start = datetime.fromtimestamp(sub.current_period_start, tz=timezone.utc)
            end = datetime.fromtimestamp(sub.current_period_end, tz=timezone.utc)
            print(f"   Sub ID: {sub.id}")
            print(f"   Status: {sub.status.upper()}")
            print(f"   Current Period: {start.strftime('%Y-%m-%d')} to {end.strftime('%Y-%m-%d')}")
            
            # Check for unpaid invoices
            invoices = stripe.Invoice.list(subscription=sub.id, status="open")
            if invoices.data:
                print(f"   ⚠️ WARNING: Customer has an unpaid invoice for ${invoices.data[0].amount_due / 100}!")
            else:
                print(f"   ✅ No open/failed invoices.")
print("\n")