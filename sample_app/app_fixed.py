"""
Sample Flask Application — "MiniBlog" (REMEDIATED)
----------------------------------------------------
This is the corrected version of app.py after applying the fixes
recommended in SECURITY_REVIEW.docx. Each fix is labeled with the
finding ID it addresses.
"""

import os
import sqlite3
from flask import Flask, request, render_template_string, abort, escape
from werkzeug.security import generate_password_hash
from functools import wraps

app = Flask(__name__)

# --- FIX for VULN-01: Load secrets from environment, never hardcode --------
app.config["SECRET_KEY"] = os.environ["APP_SECRET_KEY"]  # set via env var / secrets manager
DB_PASSWORD = os.environ.get("DB_PASSWORD")


def get_db():
    conn = sqlite3.connect("blog.db")
    return conn


def require_admin(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        # FIX for VULN-06: enforce authentication/authorization
        token = request.headers.get("Authorization")
        if not token or not is_valid_admin_token(token):
            abort(403)
        return fn(*args, **kwargs)
    return wrapper


def is_valid_admin_token(token: str) -> bool:
    # Placeholder — real implementation validates against session store / JWT
    return token == os.environ.get("ADMIN_TOKEN")


# --- FIX for VULN-02: Parameterized queries -------------------------------
@app.route("/user")
def get_user():
    username = request.args.get("username", "")
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, username, email FROM users WHERE username = ?", (username,)
    )
    row = cur.fetchone()
    return {"user": row}


# --- FIX for VULN-03: Auto-escaping via Jinja2 templates -------------------
@app.route("/greet")
def greet():
    name = request.args.get("name", "friend")
    # Using {{ name }} lets Jinja2 autoescape the value; no manual concatenation.
    return render_template_string("<h1>Hello, {{ name }}!</h1>", name=name)


# --- FIX for VULN-04: Strong, salted password hashing ----------------------
def hash_password(password: str) -> str:
    # werkzeug's generate_password_hash uses PBKDF2/scrypt with a random salt.
    return generate_password_hash(password)


@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username")
    password = request.form.get("password")
    if not username or not password:
        abort(400)
    hashed = hash_password(password)
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed)
    )
    conn.commit()
    return {"status": "registered"}


# --- FIX for VULN-05: Use a safe serialization format ----------------------
@app.route("/load_session", methods=["POST"])
def load_session():
    import json
    try:
        session_obj = json.loads(request.data)
    except ValueError:
        abort(400)
    return {"loaded": True, "data": session_obj}


# --- FIX for VULN-06: Auth-gated destructive action -------------------------
@app.route("/admin/delete_user")
@require_admin
def delete_user():
    user_id = request.args.get("id")
    if not user_id or not user_id.isdigit():
        abort(400)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    return {"status": "deleted"}


# --- FIX for VULN-07: Debug mode disabled, config via environment ----------
if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug_mode, host="127.0.0.1")
