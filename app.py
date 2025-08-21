# app.py
import os
from flask import Flask, jsonify, request, make_response
from dotenv import load_dotenv
from flask_cors import CORS
from supabase import create_client, Client
from supabase.lib.client_options import ClientOptions

# ────────────────────────── env / Supabase ──────────────────────────
load_dotenv()

SUPABASE_URL = os.environ["SUPABASE_URL"]
SERVICE_KEY = os.environ["SUPABASE_SERVICE_ROLE"]  # service role (server-only!)
ANON_KEY = os.getenv("SUPABASE_ANON")  # optional but recommended

# Use two clients: admin (service role) and public (anon)
sb_admin: Client = create_client(
    SUPABASE_URL,
    SERVICE_KEY,
    options=ClientOptions(auto_refresh_token=False, persist_session=False),
)
sb_public: Client = create_client(
    SUPABASE_URL,
    ANON_KEY or SERVICE_KEY,  # fall back to service key if anon isn't provided
    options=ClientOptions(auto_refresh_token=False, persist_session=False),
)

# ────────────────────────── Flask + CORS ────────────────────────────
app = Flask(__name__)
CORS_ORIGINS = ["http://localhost:3000", "http://localhost:5173"]
# Allow CORS for /signup, /login, /ping and any route under /api/
CORS(app, resources={r"/(signup|login|api/.*|ping)": {"origins": CORS_ORIGINS}})

def err(msg, code=400):
    """Consistent JSON error helper."""
    return make_response({"error": str(msg)}, code)

# ───────────────────────── health check ─────────────────────────────
@app.get("/ping")
def ping():
    return {"status": "ok"}

# ───────────────────────── signup route ─────────────────────────────
@app.post("/signup")
def signup():
    body = request.get_json(force=True, silent=True) or {}
    email = body.get("email")
    password = body.get("password")
    if not email or not password:
        return err("email and password required", 400)

    # 1) create auth user (admin privileges required)
    try:
        res = sb_admin.auth.admin.create_user(
            {"email": email, "password": password, "email_confirm": True}
        )
        uid = res.user.id
    except Exception as e:
        return err(f"auth create failed: {e}", 400)

    # 2) upsert profile
    profile = {
        "user_id": uid,
        "email": email,
        "first_name": body.get("first_name"),
        "last_name": body.get("last_name"),
        "phone": body.get("phone"),
        "birthday": body.get("birthday"),
        "is_admin": False,
        "signed_waiver": False,
    }
    try:
        sb_admin.table("user_profiles").upsert(profile).execute()
    except Exception as e:
        # roll back the auth user if profile insert fails
        try:
            # v2: hard-delete by default (no 'force' kwarg)
            sb_admin.auth.admin.delete_user(uid)
        except Exception:
            pass
        return err(f"profile insert failed: {e}", 500)

    return {"user_id": uid}, 201

# ───────────────────────── login route ──────────────────────────────
@app.post("/login")
def login():
    """
    JSON body:
    { "email": "user@example.com", "password": "secret123" }
    """
    body = request.get_json(force=True, silent=True) or {}
    email = body.get("email")
    password = body.get("password")
    if not email or not password:
        return err("email and password required", 400)

    try:
        res = sb_public.auth.sign_in_with_password({"email": email, "password": password})
        session = res.session
        return {
            "access_token": session.access_token,
            "refresh_token": session.refresh_token,
            "user_id": res.user.id,
            "expires_in": session.expires_in,
            "token_type": session.token_type,
        }, 200
    except Exception as e:
        return err(f"invalid login: {e}", 401)

# ───────────────────────── list profiles (dev) ─────────────────────
@app.get("/api/profiles")
def list_profiles():
    try:
        rows = sb_admin.table("user_profiles").select("*").execute().data
        return jsonify(rows)
    except Exception as e:
        return err(f"query failed: {e}", 500)

# ───────────────────────── run dev server ──────────────────────────
if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    app.run(host="0.0.0.0", port=port, debug=True)
