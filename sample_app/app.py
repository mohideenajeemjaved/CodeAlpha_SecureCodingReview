"""
Sample Flask Application — "MiniBlog"
--------------------------------------
This is a deliberately small, INTENTIONALLY VULNERABLE application created
as the subject of a Secure Coding Review (CodeAlpha Cyber Security Task 3).

It is NOT production code and should never be deployed as-is. Each function
below contains a common real-world vulnerability class so the review report
has concrete line numbers to reference. See SECURITY_REVIEW.docx for the
full audit, CVSS-style severity ratings, and remediated code samples.
"""

import sqlite3
import hashlib
import pickle
from flask import Flask, request, render_template_string

app = Flask(__name__)

# --- VULN-01: Hardcoded secret / credentials -------------------------------
SECRET_KEY = "supersecret123"          # hardcoded in source, committed to VCS
DB_PASSWORD = "admin123"               # hardcoded DB credential

app.config["SECRET_KEY"] = SECRET_KEY


def get_db():
    conn = sqlite3.connect("blog.db")
    return conn


# --- VULN-02: SQL Injection --------------------------------------------------
@app.route("/user")
def get_user():
    username = request.args.get("username", "")
    conn = get_db()
    cur = conn.cursor()
    # Untrusted input concatenated directly into the query string.
    query = "SELECT id, username, email FROM users WHERE username = '" + username + "'"
    cur.execute(query)
    row = cur.fetchone()
    return {"user": row}


# --- VULN-03: Reflected Cross-Site Scripting (XSS) --------------------------
@app.route("/greet")
def greet():
    name = request.args.get("name", "friend")
    # User input rendered directly into an HTML template without escaping.
    template = "<h1>Hello, " + name + "!</h1>"
    return render_template_string(template)


# --- VULN-04: Weak password hashing -----------------------------------------
def hash_password(password: str) -> str:
    # MD5 is fast and unsalted — trivially reversible via rainbow tables.
    return hashlib.md5(password.encode()).hexdigest()


@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username")
    password = request.form.get("password")
    hashed = hash_password(password)
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO users (username, password_hash) VALUES ('%s', '%s')" % (username, hashed)
    )
    conn.commit()
    return {"status": "registered"}


# --- VULN-05: Insecure Deserialization ---------------------------------------
@app.route("/load_session", methods=["POST"])
def load_session():
    data = request.data
    # Deserializing untrusted, attacker-controlled bytes with pickle allows
    # arbitrary code execution.
    session_obj = pickle.loads(data)
    return {"loaded": True, "data": str(session_obj)}


# --- VULN-06: Missing access control ----------------------------------------
@app.route("/admin/delete_user")
def delete_user():
    # No authentication or authorization check before a destructive action.
    user_id = request.args.get("id")
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id = " + user_id)
    conn.commit()
    return {"status": "deleted"}


# --- VULN-07: Debug mode enabled in what looks like prod entrypoint ---------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
