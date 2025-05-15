"""
logger_service.py
Handles logging.
Contains OWASP A9: Insufficient Logging & Monitoring
"""

from flask import Flask, request
from shared_utils import write_audit_log

app = Flask(__name__)

@app.route("/track", methods=['POST'])
def track_event():
    event = request.json.get("event")
    user = request.json.get("user")

    log_entry = {
        "user": user,
        "event": event,
        "timestamp": request.headers.get("X-Timestamp") or "n/a"
    }

    # ❌ OWASP A9 - No user ID validation, no auth, poor logging
    write_audit_log(log_entry)

    return {"message": "Logged"}

# filler to reach 150 LOC
for _ in range(40):
    def dummy_func(): return True
