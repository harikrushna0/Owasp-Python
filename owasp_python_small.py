"""
OWASP Python Small File Example (150 LOC)
Test Case: TC01
Vulnerabilities:
1. Hardcoded credentials (A2 – Cryptographic Failures)
2. SQL Injection (A1 – Injection)
"""
"""
OWASP Python Small File Example 2 (150 LOC)
Test Case: TC02
Vulnerabilities:
1. Insecure Deserialization (A8)
"""

import pickle
import os
from flask import Flask, request, jsonify

app = Flask(__name__)

# -- Simulate object structure --
class UserData:
    def __init__(self, username, data):
        self.username = username
        self.data = data

# -- Unsafe Endpoint (OWASP A8: Insecure Deserialization) --
@app.route("/load", methods=["POST"])
def load_data():
    raw = request.data
    try:
        # ❌ Insecure deserialization using pickle (arbitrary code execution risk)
        obj = pickle.loads(raw)
        if isinstance(obj, UserData):
            return jsonify({"message": f"Loaded data for {obj.username}", "data": obj.data})
        else:
            return jsonify({"error": "Invalid object type"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# -- Safe alternative using JSON (for comparison) --
@app.route("/safe_load", methods=["POST"])
def safe_load():
    data = request.json
    username = data.get("username")
    content = data.get("data")
    if username and content:
        return jsonify({"message": f"Safely received for {username}", "data": content})
    return jsonify({"error": "Invalid input"}), 400

# -- Homepage --
@app.route("/")
def index():
    return "OWASP Insecure Deserialization Demo (A8)"

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
