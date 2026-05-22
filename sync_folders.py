from core import sb_admin, log

def run_sync():
    log.info("Starting Master Folder Synchronization...")
    
    # 1. Get all Master Folders (user_memberships)
    mems = sb_admin.table("user_memberships").select("id, owner_user_id").execute().data
    log.info(f"Found {len(mems)} memberships to check.")

    updated_count = 0

    for mem in mems:
        mem_id = mem["id"]
        
        # 2. Find the most recent "ticket" for this membership
        periods = sb_admin.table("membership_periods") \
            .select("period_start, period_end, source") \
            .eq("user_membership_id", mem_id) \
            .eq("is_voided", False) \
            .order("period_end", desc=True) \
            .limit(1) \
            .execute().data
            
        if periods:
            latest_ticket = periods[0]
            start_iso = latest_ticket["period_start"]
            end_iso = latest_ticket["period_end"]
            source = latest_ticket["source"] # 'manual' or 'stripe'
            
            # Map 'source' to 'payment_provider' so cash shows up correctly
            provider = "cash" if source == "manual" else "stripe"

            # 3. Copy the dates up to the Master Folder
            sb_admin.table("user_memberships").update({
                "current_period_start": start_iso,
                "current_period_end": end_iso,
                "payment_provider": provider
            }).eq("id", mem_id).execute()
            
            updated_count += 1

    log.info(f"🏁 Sync Complete. {updated_count} master folders updated with exact expiration dates.")

if __name__ == "__main__":
    run_sync()