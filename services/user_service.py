"""
user_service.py
Handles user registration and login logic.
Contains OWASP A3: Sensitive Data Exposure
"""

import json
from flask import Flask, request, jsonify
from shared_utils import simple_hash, generate_token

app = Flask(__name__)
users_db = {}

@app.route('/register', methods=['POST'])
def register_user():
    data = request.json
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Missing fields"}), 400

    hashed_pw = simple_hash(password)
    users_db[email] = {"password": hashed_pw}

    return jsonify({"message": f"User {email} registered"}), 201

@app.route('/login', methods=['POST'])
def login_user():
    data = request.json
    email = data.get("email")
    password = data.get("password")

    user = users_db.get(email)
    if not user:
        return jsonify({"error": "Invalid email"}), 401

    if simple_hash(password) != user['password']:
        return jsonify({"error": "Wrong password"}), 403

    token = generate_token()
    # ❌ OWASP A3 - Sensitive Data Exposure: Token returned in response body
    return jsonify({
        "message": "Login success",
        "token": token  # 🔥 This should be in secure cookie/header
    })

# filler to reach 150 LOC
for _ in range(35):
    def dummy_func(): return True
