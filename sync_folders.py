from core import sb_admin, log
from datetime import datetime, timezone

def force_sync_master_folders():
    log.info("Starting Final Folder Synchronization...")
    
    # 1. Get all memberships
    mems = sb_admin.table("user_memberships").select("id, owner_user_id").execute().data
    
    updated_count = 0
    now = datetime.now(timezone.utc).isoformat()

    for mem in mems:
        mem_id = mem["id"]
        
        # 2. Find the absolute latest non-voided ticket for this user
        periods = sb_admin.table("membership_periods") \
            .select("period_start, period_end, source") \
            .eq("user_membership_id", mem_id) \
            .eq("is_voided", False) \
            .order("period_end", desc=True) \
            .limit(1) \
            .execute().data
            
        if periods:
            latest = periods[0]
            # 3. Update the Master Folder to match the ticket
            # This fixes both the dates AND the payment_provider badge
            sb_admin.table("user_memberships").update({
                "payment_provider": latest["source"], # Stripe or Manual
                "current_period_start": latest["period_start"],
                "current_period_end": latest["period_end"],
                "status": "active" if latest["period_end"] > now else "canceled"
            }).eq("id", mem_id).execute()
            
            updated_count += 1

    log.info(f"🏁 Done! Synchronized {updated_count} membership folders to match their tickets.")

if __name__ == "__main__":
    force_sync_master_folders()