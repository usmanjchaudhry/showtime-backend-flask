import os
import stripe
from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta

# Define the "Blueprint" (a mini app)
admin_bp = Blueprint('admin', __name__)

# --- CONFIGURATION ---
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
# ---------------------

# Helper: Security Check (Update this later with real database check)
def is_admin(user_id):
    return True 

@admin_bp.route('/revenue', methods=['GET'])
def get_revenue():
    # 1. Security Check
    user_id = request.headers.get('User-Id')
    if not is_admin(user_id):
        return jsonify({"error": "Unauthorized"}), 403

    # 2. Get Filters
    period = request.args.get('period', '30d')
    
    now = datetime.now()
    if period == 'today':
        start_date = now.replace(hour=0, minute=0, second=0)
    elif period == '7d':
        start_date = now - timedelta(days=7)
    elif period == 'mtd':
        start_date = now.replace(day=1, hour=0, minute=0, second=0)
    else: # Default 30d
        start_date = now - timedelta(days=30)

    start_ts = int(start_date.timestamp())
    end_ts = int(now.timestamp())

    try:
        # 3. Fetch from Stripe
        charges = stripe.Charge.list(
            created={'gte': start_ts, 'lte': end_ts},
            limit=100, 
            status='succeeded' 
        )

        # 4. Calculate Totals
        total_revenue_cents = 0
        daily_breakdown = {}

        for charge in charges.auto_paging_iter():
            amount = charge['amount']
            total_revenue_cents += amount
            
            # Group by Day
            ts = int(charge['created'])
            day_str = datetime.fromtimestamp(ts).strftime('%Y-%m-%d')
            
            if day_str not in daily_breakdown:
                daily_breakdown[day_str] = 0
            daily_breakdown[day_str] += amount

        return jsonify({
            "period": period,
            "total_revenue": total_revenue_cents / 100,
            "breakdown": [
                {"date": date, "amount": cents / 100} 
                for date, cents in sorted(daily_breakdown.items())
            ]
        })

    except Exception as e:
        print(f"Stripe Error: {e}")
        return jsonify({"error": str(e)}), 500