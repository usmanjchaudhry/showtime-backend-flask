# app.py
import os
import traceback
from time import perf_counter
from uuid import uuid4

from flask import Flask, jsonify, request, make_response, g
from flask_cors import CORS
from werkzeug.exceptions import HTTPException

from core import log, err, FRONTEND_URL

from routes.auth import auth_bp
from routes.checkout import checkout_bp
from routes.user import user_bp
from routes.admin import admin_bp

app = Flask(__name__)

CORS_ORIGINS = [
    "http://localhost:3000", 
    "http://localhost:5173", 
    "https://showtime-front-end.vercel.app",
    "https://www.showtimeboxinggym.com", 
    FRONTEND_URL
]

CORS(
    app,
    resources={r"/*": {"origins": CORS_ORIGINS}},
    supports_credentials=True,
    allow_headers=["Content-Type", "Authorization", "x-request-id", "Stripe-Signature"],
    expose_headers=["x-request-id"],
)

# ✅ Fix: Removed url_prefixes. The blueprints now use exact paths.
app.register_blueprint(auth_bp)
app.register_blueprint(checkout_bp)
app.register_blueprint(user_bp)
app.register_blueprint(admin_bp)

@app.before_request
def _log_request_start():
    g._start = perf_counter()
    g._rid = request.headers.get("x-request-id") or uuid4().hex[:8]
    log.info(f"[{g._rid}] → {request.method} {request.path}")

@app.after_request
def _log_response(resp):
    dur_ms = (perf_counter() - g.get("_start", perf_counter())) * 1000
    rid = g.get("_rid", "-")
    log.info(f"[{rid}] ← {resp.status_code} {dur_ms:.1f}ms")
    resp.headers["x-request-id"] = rid
    return resp

@app.errorhandler(Exception)
def _unhandled(e):
    rid = g.get("_rid", "-")
    if isinstance(e, HTTPException):
        return make_response({"error": e.description}, e.code)
    log.error(f"[{rid}] !!! {type(e).__name__}: {e}\n{traceback.format_exc()}")
    return err("internal server error", 500)

@app.get("/")
def root():
    return jsonify({"ok": True, "service": "showtime-backend"})

@app.get("/ping")
def ping():
    return {"status": "ok"}

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    log.info(f"Starting server on 0.0.0.0:{port}  FRONTEND_URL={FRONTEND_URL}")
    app.run(host="0.0.0.0", port=port, debug=True)