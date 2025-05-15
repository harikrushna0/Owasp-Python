"""
OWASP Python Medium File Example (approx 500 LOC)
Test Case: TC02
Vulnerabilities:
1. Insecure Deserialization (A8 – Software and Data Integrity Failures)
2. XSS via HTML Injection (A3 – Injection)
"""

import json
import pickle  # ❌ Used for insecure deserialization
from flask import Flask, request, render_template_string, make_response, redirect, url_for
import re
import os
import datetime
import sqlite3
import uuid

app = Flask(__name__)

# -- Simulated user storage (in-memory for this example) --
user_store = {}

def init_db():
    conn = sqlite3.connect("userstore.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user TEXT,
            action TEXT,
            timestamp TEXT
        )
    """)
    conn.commit()
    conn.close()

# -- Home route --
@app.route("/")
def home():
    return "Welcome to the OWASP Python Medium App"

# -- Registration route --
@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if not username or not password or not email:
        return {"error": "Missing fields"}, 400

    if username in user_store:
        return {"error": "User already exists"}, 409

    user_store[username] = {
        "email": email,
        "password": password
    }
    return {"message": "User registered"}, 201

# -- Simulate login --
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    user = user_store.get(username)
    if user and user["password"] == password:
        resp = make_response({"message": "Logged in!"})
        resp.set_cookie("username", username)
        log_user_action(username, "login")
        return resp
    return {"error": "Invalid login"}, 401

# -- 🔥 Vulnerable: XSS Injection (OWASP A3) --
@app.route("/profile", methods=["GET"])
def profile():
    username = request.cookies.get("username")
    bio = request.args.get("bio")

    if not username or username not in user_store:
        return redirect(url_for('home'))

    # ❌ Unsanitized HTML injected into template
    html_template = f"""
        <html>
            <h2>Welcome, {username}</h2>
            <p>Your bio:</p>
            <div>{bio}</div>  <!-- XSS injection point -->
            <form action="/profile" method="get">
                <textarea name="bio" rows="4" cols="50" placeholder="Update your bio"></textarea><br/>
                <input type="submit" value="Update Bio"/>
            </form>
        </html>
    """

    return render_template_string(html_template)

# -- Activity log function --
def log_user_action(user, action):
    timestamp = datetime.datetime.now().isoformat()
    conn = sqlite3.connect("userstore.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO logs (user, action, timestamp) VALUES (?, ?, ?)", (user, action, timestamp))
    conn.commit()
    conn.close()

@app.route("/log_action", methods=["POST"])
def log_action():
    data = request.json
    user = data.get("user")
    action = data.get("action")
    if not user or not action:
        return {"error": "Missing user or action"}, 400
    log_user_action(user, action)
    return {"status": "logged"}

# -- 🔥 Vulnerable: Insecure Deserialization (OWASP A8) --
@app.route("/upload-session", methods=["POST"])
def upload_session():
    """
    This simulates restoring a session sent from client.
    ❌ The pickle module can execute arbitrary code on deserialization!
    """
    blob = request.data
    try:
        session = pickle.loads(blob)  # 🧨 Insecure deserialization
        return {"status": "session restored", "user": session.get("username")}
    except Exception as e:
        return {"error": str(e)}, 400

# -- Safe version using JSON --
@app.route("/upload-session-safe", methods=["POST"])
def upload_session_safe():
    try:
        session = json.loads(request.data)
        return {"user": session.get("username"), "restored": True}
    except json.JSONDecodeError:
        return {"error": "Invalid session format"}, 400

# -- Export user data (safe) --
@app.route("/export", methods=["GET"])
def export_data():
    username = request.args.get("username")
    if username not in user_store:
        return {"error": "User not found"}, 404
    user = user_store[username]
    return {
        "username": username,
        "email": user["email"]
    }

# -- Utility function (dummy) --
def mask_email(email):
    parts = email.split("@")
    if len(parts) == 2:
        return parts[0][:2] + "***@" + parts[1]
    return "***"

# -- Password reset request --
@app.route("/reset-password", methods=["POST"])
def reset_password():
    data = request.json
    email = data.get("email")

    for user, info in user_store.items():
        if info["email"] == email:
            token = str(uuid.uuid4())
            log_user_action(user, "password_reset_requested")
            return {"message": f"Reset link: /reset?token={token}"}
    return {"error": "Email not found"}, 404

# -- Password reset form (simple) --
@app.route("/reset", methods=["GET", "POST"])
def reset():
    if request.method == "GET":
        token = request.args.get("token")
        # Here, in real app, you'd validate token; skip for demo
        return f"""
            <form action="/reset?token={token}" method="post">
                <label>New Password:</label><input type="password" name="new_password"/>
                <input type="submit" value="Reset Password"/>
            </form>
        """
    else:
        token = request.args.get("token")
        new_password = request.form.get("new_password")
        # In a real app, verify token and map to user
        # For demo, we just accept and update first user found
        if not new_password:
            return "Password cannot be empty", 400
        # Unsafe: just pick first user to reset (demo purposes)
        for user in user_store.keys():
            user_store[user]["password"] = new_password
            log_user_action(user, "password_reset")
            break
        return "Password reset successful"

# -- Display user logs --
@app.route("/user_logs", methods=["GET"])
def user_logs():
    username = request.args.get("username")
    if not username or username not in user_store:
        return {"error": "User not found"}, 404
    conn = sqlite3.connect("userstore.db")
    cursor = conn.cursor()
    cursor.execute("SELECT action, timestamp FROM logs WHERE user=? ORDER BY timestamp DESC LIMIT 10", (username,))
    logs = cursor.fetchall()
    conn.close()

    logs_html = "<ul>"
    for action, timestamp in logs:
        logs_html += f"<li>{timestamp}: {action}</li>"
    logs_html += "</ul>"

    return f"""
    <html>
    <h2>Last 10 actions for {username}</h2>
    {logs_html}
    </html>
    """

# -- Basic search (unsafe for demonstration) --
@app.route("/search", methods=["GET"])
def search():
    term = request.args.get("term", "")
    # ❌ Unsanitized output - vulnerable to reflected XSS if term contains script
    return f"<p>Search results for <b>{term}</b> (not real results)</p>"

# -- Cookie testing --
@app.route("/cookie_test")
def cookie_test():
    username = request.cookies.get("username", "Guest")
    return f"<p>Cookie test: Hello, {username}</p>"

# -- Logout route --
@app.route("/logout")
def logout():
    resp = make_response(redirect(url_for("home")))
    resp.set_cookie("username", "", expires=0)
    return resp

# -- Health check endpoint --
@app.route("/health")
def health():
    return {"status": "OK"}

# -- Additional utilities and helpers --

# Function to validate email format (basic)
def is_valid_email(email):
    regex = r"^[\w\.-]+@[\w\.-]+\.\w+$"
    return re.match(regex, email) is not None

# Endpoint to validate emails (dummy)
@app.route("/validate_email", methods=["POST"])
def validate_email():
    data = request.json
    email = data.get("email")
    if not email or not is_valid_email(email):
        return {"valid": False}, 400
    return {"valid": True}

# -- Run server --
if __name__ == "__main__":
    init_db()
    app.run(debug=True)
