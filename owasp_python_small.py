"""
OWASP Python Small File Example (150 LOC)
Test Case: TC01
Vulnerabilities:
1. Hardcoded credentials (A2 – Cryptographic Failures)
2. SQL Injection (A1 – Injection)
"""

import sqlite3
from flask import Flask, request

app = Flask(__name__)

# -- Database Setup --
def init_db():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT
        )
    """)
    conn.commit()
    conn.close()

# -- Vulnerable: Hardcoded Credentials (OWASP A2) --
def authenticate_static():
    username = request.args.get("username")
    password = request.args.get("password")
    
    # ❌ Hardcoded credentials
    if username == "admin" and password == "admin123":
        return "Login successful as admin"
    else:
        return "Invalid credentials"

# -- Vulnerable: SQL Injection (OWASP A1) --
@app.route("/login", methods=["GET"])
def login():
    username = request.args.get("username")
    password = request.args.get("password")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # ❌ Vulnerable SQL query
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    print(f"Executing: {query}")
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()

    if result:
        return f"Welcome back, {username}!"
    else:
        return "Login failed"

# -- Safe Registration --
@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username")
    password = request.form.get("password")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
    conn.commit()
    conn.close()
    return "User registered!"

# -- Safe version of login using parameterized queries --
@app.route("/safe_login", methods=["POST"])
def safe_login():
    username = request.form.get("username")
    password = request.form.get("password")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
    user = cursor.fetchone()
    conn.close()

    if user:
        return f"Secure Welcome, {username}"
    return "Secure Login Failed"

# -- App run --
if __name__ == "__main__":
    init_db()
    app.run(debug=True)
