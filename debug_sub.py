import os
import stripe
from dotenv import load_dotenv

load_dotenv()
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

def inspect_ghost_subscription():
    # This is one of the IDs that showed "Active but missing dates" in your logs
    TARGET_ID = "sub_1SrQrvLQmZaxf1vef93tbajT" 
    
    print(f"--- INSPECTING {TARGET_ID} ---")
    
    try:
        sub = stripe.Subscription.retrieve(TARGET_ID)
        
        print(f"Status: {sub.status}")
        print(f"Current Period Start: {sub.get('current_period_start')}")
        print(f"Current Period End:   {sub.get('current_period_end')}")
        
        print("\n--- RAW KEYS AVAILABLE ---")
        # This will show us every single field attached to this object
        print(list(sub.keys()))
        
        print("\n--- FULL DUMP ---")
        print(sub)
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    inspect_ghost_subscription()