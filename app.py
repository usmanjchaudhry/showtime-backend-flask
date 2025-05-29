# app.py
import os
from flask import Flask, jsonify, request, make_response
from dotenv import load_dotenv
from flask_cors import CORS
from supabase import create_client, Client

# ────────────────────────── env / Supabase ──────────────────────────
load_dotenv()
SUPABASE_URL  = os.environ["SUPABASE_URL"]
SERVICE_KEY   = os.environ["SUPABASE_SERVICE_ROLE"]
sb: Client    = create_client(SUPABASE_URL, SERVICE_KEY)

# ────────────────────────── Flask + CORS ────────────────────────────
app = Flask(__name__)
CORS_ORIGINS = ["http://localhost:3000", "http://localhost:5173"]
# Allow CORS for /signup, /login, and any route under /api/
CORS(app, resources={r"/(signup|login|api/.*)": {"origins": CORS_ORIGINS}})

def err(msg, code):
    """Consistent JSON error helper."""
    return make_response({"error": msg}, code)

# ───────────────────────── health check ─────────────────────────────
@app.get("/ping")
def ping():
    return {"status": "ok"}

# ───────────────────────── signup route ─────────────────────────────
@app.post("/signup")
def signup():
    body            = request.get_json(force=True)
    email, password = body.get("email"), body.get("password")
    if not email or not password:
        return err("email and password required", 400)

    # 1) create auth user
    try:
        res = sb.auth.admin.create_user(
            {"email": email, "password": password, "email_confirm": True}
        )
        uid = res.user.id
    except Exception as e:
        return err(f"auth create failed: {e}", 400)

    # 2) upsert profile
    profile = {
        "user_id":       uid,
        "email":         email,
        "first_name":    body.get("first_name"),
        "last_name":     body.get("last_name"),
        "phone":         body.get("phone"),
        "birthday":      body.get("birthday"),
        "is_admin":      False,
        "signed_waiver": False,
    }
    try:
        sb.table("user_profiles").upsert(profile).execute()
    except Exception as e:
        sb.auth.admin.delete_user(uid, force=True)  # roll back
        return err(f"profile insert failed: {e}", 500)

    return {"user_id": uid}, 201

# ───────────────────────── login route ──────────────────────────────
@app.post("/login")
def login():
    """
    JSON body:
    { "email": "user@example.com", "password": "secret123" }
    """
    body            = request.get_json(force=True)
    email, password = body.get("email"), body.get("password")
    if not email or not password:
        return err("email and password required", 400)

    try:
        res      = sb.auth.sign_in_with_password({"email": email, "password": password})
        session  = res.session
        return {
            "access_token":  session.access_token,
            "refresh_token": session.refresh_token,
            "user_id":       res.user.id,
            "expires_in":    session.expires_in,
            "token_type":    session.token_type,
        }, 200
    except Exception as e:
        return err(str(e), 401)

# ───────────────────────── list profiles (dev) ─────────────────────
@app.get("/api/profiles")
def list_profiles():
    rows = sb.table("user_profiles").select("*").execute().data
    return jsonify(rows)

# ───────────────────────── run dev server ──────────────────────────
if __name__ == "__main__":
    app.run(port=8080, debug=True)
