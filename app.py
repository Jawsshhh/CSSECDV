from flask import Flask, request, jsonify, send_from_directory
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from pymongo import MongoClient
from pymongo.server_api import ServerApi
from bson import ObjectId
from datetime import datetime, timedelta
import hashlib
from functools import wraps
import os
from dotenv import load_dotenv
import bcrypt
import re


app = Flask(__name__, static_folder='frontend', static_url_path='')
CORS(app)

app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET", "super-secret-fallback-key")
jwt = JWTManager(app)

uri = os.getenv("MONGO_DB_URI")
#MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
client = MongoClient(uri, server_api=ServerApi('1'))
db = client["hr_logging_system"]

users_col       = db["users"]
attendance_col  = db["attendance"]
leave_col       = db["leave_requests"]
payslips_col    = db["payslips"]
logs_col        = db["system_logs"]

# Helper functions
def hash_pw(pw): # Password Hashing
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(pw.encode('utf-8'), salt)
    return hashed.decode('utf-8')
def check_pw(plain_pw, hashed_pw):
    # Safely compares a plain text password against the stored bcrypt hash
    return bcrypt.checkpw(plain_pw.encode('utf-8'), hashed_pw.encode('utf-8'))

def serialize(doc):
    if doc is None:
        return None
    if isinstance(doc, list):
        return [serialize(d) for d in doc]
    if isinstance(doc, dict):
        return {k: (str(v) if isinstance(v, ObjectId) else serialize(v)) for k, v in doc.items()}
    return doc

def log_action(user_id, action, details=""):
    logs_col.insert_one({
        "user_id": user_id,
        "action": action,
        "details": details,
        "timestamp": datetime.utcnow().isoformat()
    })

def seed_defaults():
    if users_col.count_documents({}) == 0:
        defaults = [
            {"username": "admin",     "password": hash_pw("admin123"),     "full_name": "System Admin",  "role": "admin",    "department": "IT",          "email": "admin@company.com"},
            {"username": "hr_staff",  "password": hash_pw("hr123"),        "full_name": "HR Manager",    "role": "hr",       "department": "HR",          "email": "hr@company.com"},
            {"username": "john_doe",  "password": hash_pw("employee123"),  "full_name": "John Doe",      "role": "employee", "department": "Engineering", "email": "john@company.com"},
            {"username": "jane_doe",  "password": hash_pw("employee123"),  "full_name": "Jane Doe",      "role": "employee", "department": "Marketing",   "email": "jane@company.com"},
        ]
        for u in defaults:
            u["created_at"] = datetime.utcnow().isoformat()
            u["password_changed_at"] = None
            u["password_history"] = [u["password"]]   # store initial hash in history
            u["security_question"] = None
            u["security_answer_hash"] = None
            u["last_login"] = None
            u["last_failed_login"] = None
        users_col.insert_many(defaults)
        print("Seeded default users.")

MAX_ATTEMPTS   = 5
LOCKOUT_MINUTES = 15

def is_account_locked(user):
    if not user.get("locked_until"):
        return False, None
    locked_until = datetime.fromisoformat(user["locked_until"])
    if datetime.utcnow() < locked_until:
        remaining = int((locked_until - datetime.utcnow()).total_seconds() / 60) + 1
        return True, remaining
    # Lockout expired 
    users_col.update_one(
        {"_id": user["_id"]},
        {"$unset": {"locked_until": "", "failed_attempts": ""}}
    )
    return False, None

def record_failed_attempt(user):
    attempts = user.get("failed_attempts", 0) + 1
    if attempts >= MAX_ATTEMPTS:
        locked_until = (datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
        users_col.update_one(
            {"_id": user["_id"]},
            {"$set": {"failed_attempts": attempts, "locked_until": locked_until}}
        )
        log_action(str(user["_id"]), "ACCOUNT_LOCKED", f"After {attempts} failed attempts")
    else:
        users_col.update_one(
            {"_id": user["_id"]},
            {"$set": {"failed_attempts": attempts}}
        )

def require_role(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                user_id = get_jwt_identity()
                user = users_col.find_one({"_id": ObjectId(user_id)})
                if not user or user.get("role") not in roles:
                    return jsonify({"error": "Forbidden"}), 403
                return fn(*args, **kwargs)
            except Exception:
                # Fail securely — any error defaults to denied
                return jsonify({"error": "Forbidden"}), 403
        return wrapper
    return decorator
# Login/Authentication
@app.route("/api/login", methods=["POST"])
def login():
    try:
        data = request.json
        if not data or not data.get("username") or not data.get("password"):
            return jsonify({"error": "Invalid credentials"}), 401

        user = users_col.find_one({"username": data.get("username")})
        if not user:
            return jsonify({"error": "Invalid credentials"}), 401

        locked, remaining = is_account_locked(user)
        if locked:
            log_action(str(user["_id"]), "LOGIN_BLOCKED", f"{remaining}min remaining")
            return jsonify({"error": f"Account locked. Try again in {remaining} minute{'s' if remaining != 1 else ''}."}), 423

        if not check_pw(data.get("password", ""), user["password"]):
            record_failed_attempt(user)
            users_col.update_one(
                {"_id": user["_id"]},
                {"$set": {"last_failed_login": datetime.utcnow().isoformat()}}
            )
            attempts_left = MAX_ATTEMPTS - user.get("failed_attempts", 0) - 1
            if attempts_left <= 0:
                return jsonify({"error": f"Account locked for {LOCKOUT_MINUTES} minutes."}), 423
            return jsonify({"error": f"Invalid credentials. {attempts_left} attempt{'s' if attempts_left != 1 else ''} remaining."}), 401

        prev_last_login        = user.get("last_login")
        prev_last_failed_login = user.get("last_failed_login")

        now_iso = datetime.utcnow().isoformat()
        users_col.update_one(
            {"_id": user["_id"]},
            {"$unset": {"failed_attempts": "", "locked_until": ""},
             "$set":   {"last_login": now_iso}}
        )
        log_action(str(user["_id"]), "LOGIN")
        access_token = create_access_token(identity=str(user["_id"]))
        return jsonify({
            "message": "Login successful",
            "token": access_token,
            "last_login":        prev_last_login,
            "last_failed_login": prev_last_failed_login,
            "user": serialize({
                "_id":        user["_id"],
                "username":   user["username"],
                "full_name":  user["full_name"],
                "role":       user["role"],
                "department": user["department"],
                "email":      user.get("email", ""),
                "security_question": user.get("security_question")
            })
        })
    except Exception as e:
        log_action("system", "LOGIN_ERROR", str(e))
        return jsonify({"error": "An error occurred. Please try again."}), 500


# User routes
@app.route("/api/users", methods=["GET"])
@jwt_required()
@require_role("admin", "hr")
def get_users():
    users = list(users_col.find({}, {"password": 0}))
    return jsonify(serialize(users))

@app.route("/api/users", methods=["POST"])
@jwt_required()
@require_role("admin")
def create_user():
    data = request.json
    if users_col.find_one({"username": data["username"]}):
        return jsonify({"error": "Username already exists"}), 400
    hashed_pw = hash_pw(data["password"])
    user = {
        "username":   data["username"],
        "password":   hashed_pw,
        "full_name":  data["full_name"],
        "role":       data["role"],
        "department": data.get("department", "General"),
        "email":      data.get("email", ""),
        "created_at": datetime.utcnow().isoformat(),
        "password_changed_at": None,
        "password_history": [hashed_pw],
        "security_question": None,
        "security_answer_hash": None,
        "last_login": None,
        "last_failed_login": None
    }
    result = users_col.insert_one(user)
    log_action(data.get("admin_id", "system"), "CREATE_USER", data["username"])
    return jsonify({"message": "User created", "id": str(result.inserted_id)}), 201

@app.route("/api/users/<user_id>", methods=["PUT"])
@jwt_required()
@require_role("admin")
def update_user(user_id):
    data = request.json
    update = {k: v for k, v in data.items() if k not in ("_id", "password")}
    if "new_password" in data:
        update["password"] = hash_pw(data["new_password"])
    users_col.update_one({"_id": ObjectId(user_id)}, {"$set": update})
    return jsonify({"message": "User updated"})

@app.route("/api/users/<user_id>", methods=["DELETE"])
@jwt_required()
@require_role("admin")
def delete_user(user_id):
    users_col.delete_one({"_id": ObjectId(user_id)})
    return jsonify({"message": "User deleted"})

# Attendance routes
@app.route("/api/attendance/timein", methods=["POST"])
@jwt_required()
def time_in():
    data = request.json
    today = datetime.utcnow().strftime("%Y-%m-%d")
    existing = attendance_col.find_one({"user_id": data["user_id"], "date": today})
    if existing and existing.get("time_in"):
        return jsonify({"error": "Already timed in today"}), 400
    now = datetime.utcnow().isoformat()
    if existing:
        attendance_col.update_one({"_id": existing["_id"]}, {"$set": {"time_in": now}})
    else:
        attendance_col.insert_one({"user_id": data["user_id"], "date": today, "time_in": now, "time_out": None, "overtime_hours": 0, "notes": ""})
    log_action(data["user_id"], "TIME_IN")
    return jsonify({"message": "Timed in", "time": now})

@app.route("/api/attendance/timeout", methods=["POST"])
@jwt_required()
def time_out():
    data = request.json
    today = datetime.utcnow().strftime("%Y-%m-%d")
    record = attendance_col.find_one({"user_id": data["user_id"], "date": today})
    if not record or not record.get("time_in"):
        return jsonify({"error": "No time-in found for today"}), 400
    if record.get("time_out"):
        return jsonify({"error": "Already timed out today"}), 400
    now = datetime.utcnow()
    hours = (now - datetime.fromisoformat(record["time_in"])).total_seconds() / 3600
    overtime = max(0, hours - 8)
    attendance_col.update_one({"_id": record["_id"]}, {"$set": {"time_out": now.isoformat(), "overtime_hours": round(overtime, 2)}})
    log_action(data["user_id"], "TIME_OUT")
    return jsonify({"message": "Timed out", "time": now.isoformat(), "hours_worked": round(hours, 2), "overtime": round(overtime, 2)})

@app.route("/api/attendance/<user_id>", methods=["GET"])
@jwt_required()
def get_attendance(user_id):
    records = list(attendance_col.find({"user_id": user_id}).sort("date", -1).limit(30))
    return jsonify(serialize(records))

@app.route("/api/attendance/all", methods=["GET"])
@jwt_required()
@require_role("admin", "hr")
def get_all_attendance():
    records = list(attendance_col.find({}).sort("date", -1).limit(100))
    enriched = []
    for r in records:
        user = users_col.find_one({"_id": ObjectId(r["user_id"])}, {"full_name": 1, "department": 1}) if ObjectId.is_valid(r.get("user_id", "")) else None
        r["full_name"] = user["full_name"] if user else r["user_id"]
        r["department"] = user.get("department", "") if user else ""
        enriched.append(r)
    return jsonify(serialize(enriched))

# Leave request functionality
@app.route("/api/leave", methods=["POST"])
@jwt_required()
def submit_leave():
    data = request.json
    leave = {
        "user_id":    data["user_id"],
        "leave_type": data["leave_type"],
        "start_date": data["start_date"],
        "end_date":   data["end_date"],
        "reason":     data.get("reason", ""),
        "status":     "pending",
        "reviewed_by": None,
        "reviewed_at": None,
        "created_at": datetime.utcnow().isoformat()
    }
    result = leave_col.insert_one(leave)
    log_action(data["user_id"], "SUBMIT_LEAVE", data["leave_type"])
    return jsonify({"message": "Leave request submitted", "id": str(result.inserted_id)}), 201

@app.route("/api/leave/<user_id>", methods=["GET"])
@jwt_required()
def get_my_leave(user_id):
    records = list(leave_col.find({"user_id": user_id}).sort("created_at", -1))
    return jsonify(serialize(records))

@app.route("/api/leave/all", methods=["GET"])
@jwt_required()
@require_role("admin", "hr")
def get_all_leave():
    records = list(leave_col.find({}).sort("created_at", -1))
    enriched = []
    for r in records:
        user = users_col.find_one({"_id": ObjectId(r["user_id"])}, {"full_name": 1, "department": 1}) if ObjectId.is_valid(r.get("user_id", "")) else None
        r["full_name"] = user["full_name"] if user else r["user_id"]
        r["department"] = user.get("department", "") if user else ""
        enriched.append(r)
    return jsonify(serialize(enriched))

@app.route("/api/leave/<leave_id>/review", methods=["PUT"])
@jwt_required()
@require_role("admin", "hr")
def review_leave(leave_id):
    data = request.json
    leave_col.update_one({"_id": ObjectId(leave_id)}, {"$set": {
        "status": data["status"],
        "reviewed_by": data["reviewed_by"],
        "reviewed_at": datetime.utcnow().isoformat()
    }})
    log_action(data["reviewed_by"], "REVIEW_LEAVE", f"{leave_id}:{data['status']}")
    return jsonify({"message": f"Leave {data['status']}"})

# Payslips (may cut)
@app.route("/api/payslips/<user_id>", methods=["GET"])
@jwt_required()
def get_payslips(user_id):
    records = list(payslips_col.find({"user_id": user_id}).sort("period", -1))
    return jsonify(serialize(records))

@app.route("/api/payslips", methods=["POST"])
@jwt_required()
@require_role("admin")
def add_payslip():
    data = request.json
    data["created_at"] = datetime.utcnow().isoformat()
    result = payslips_col.insert_one(data)
    return jsonify({"message": "Payslip added", "id": str(result.inserted_id)}), 201

# ─── REPORTS ──────────────────────────────────────────────────────────────────
@app.route("/api/reports/summary", methods=["GET"])
@jwt_required()
@require_role("admin", "hr")
def summary_report():
    total_users   = users_col.count_documents({})
    pending_leave = leave_col.count_documents({"status": "pending"})
    today         = datetime.utcnow().strftime("%Y-%m-%d")
    present_today = attendance_col.count_documents({"date": today, "time_in": {"$ne": None}})
    ot_agg        = list(attendance_col.aggregate([{"$group": {"_id": None, "total": {"$sum": "$overtime_hours"}}}]))
    ot_hours      = ot_agg[0]["total"] if ot_agg else 0
    return jsonify({
        "total_users": total_users,
        "pending_leave": pending_leave,
        "present_today": present_today,
        "total_overtime_hours": round(ot_hours, 2)
    })

# Logging
@app.route("/api/logs", methods=["GET"])
@jwt_required()
@require_role("admin")
def get_logs():
    logs = list(logs_col.find({}).sort("timestamp", -1).limit(100))
    return jsonify(serialize(logs))




ALLOWED_SECURITY_QUESTIONS = [
    "What was the name of your first pet?",
    "What city were you born in?",
    "What was the make and model of your first car?",
    "What is your oldest sibling's middle name?",
    "What was the name of your elementary school?",
    "What was the street name you grew up on?",
    "What was your childhood nickname?",
    "What is the middle name of your youngest child?",
    "In what city did your parents meet?",
    "What was the name of your first employer?",
]

@app.route("/api/security-questions", methods=["GET"])
def list_security_questions():
    return jsonify({"questions": ALLOWED_SECURITY_QUESTIONS})

@app.route("/api/security-question", methods=["POST"])
@jwt_required()
def set_security_question():
    try:
        user_id = get_jwt_identity()
        data = request.json
        question = data.get("question", "").strip()
        answer   = data.get("answer", "").strip().lower()

        if question not in ALLOWED_SECURITY_QUESTIONS:
            return jsonify({"error": "Invalid security question"}), 400
        if len(answer) < 3:
            return jsonify({"error": "Answer is too short"}), 400

        answer_hash = hash_pw(answer)
        users_col.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"security_question": question, "security_answer_hash": answer_hash}}
        )
        log_action(user_id, "SET_SECURITY_QUESTION")
        return jsonify({"message": "Security question saved"})
    except Exception as e:
        return jsonify({"error": "Failed to save security question"}), 500

@app.route("/api/security-question/<user_id>", methods=["GET"])
@jwt_required()
def get_security_question(user_id):
    caller_id = get_jwt_identity()
    if caller_id != user_id:
        return jsonify({"error": "Forbidden"}), 403
    user = users_col.find_one({"_id": ObjectId(user_id)}, {"security_question": 1})
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"security_question": user.get("security_question")})


# ─── CHANGE PASSWORD ──────────────────────────────────────────────────────────

PASSWORD_MIN_AGE_HOURS = 24
PASSWORD_HISTORY_DEPTH = 5

def _validate_new_password(new_pw: str):
    if len(new_pw) < 8:
        return "Password must be at least 8 characters."
    if not re.search(r'[A-Z]', new_pw):
        return "Password must contain at least one uppercase letter."
    if not re.search(r'[a-z]', new_pw):
        return "Password must contain at least one lowercase letter."
    if not re.search(r'\d', new_pw):
        return "Password must contain at least one digit."
    if not re.search(r'[^A-Za-z0-9]', new_pw):
        return "Password must contain at least one special character."
    return None

@app.route("/api/change-password", methods=["POST"])
@jwt_required()
def change_password():
    try:
        user_id = get_jwt_identity()
        data    = request.json
        current_pw = data.get("current_password", "")
        new_pw     = data.get("new_password", "")
        sec_answer = data.get("security_answer", "").strip().lower()

        user = users_col.find_one({"_id": ObjectId(user_id)})
        if not user:
            return jsonify({"error": "User not found"}), 404

        # #13 Re-authenticate: verify current password
        if not check_pw(current_pw, user["password"]):
            log_action(user_id, "CHANGE_PASSWORD_FAIL", "Bad current password")
            return jsonify({"error": "Current password is incorrect."}), 401

        # #9 Security question verification
        sec_q_hash = user.get("security_answer_hash")
        if not sec_q_hash:
            return jsonify({"error": "Please set a security question before changing your password."}), 400
        if not check_pw(sec_answer, sec_q_hash):
            log_action(user_id, "CHANGE_PASSWORD_FAIL", "Bad security answer")
            return jsonify({"error": "Security answer is incorrect."}), 401

        # #11 Minimum password age
        changed_at_str = user.get("password_changed_at")
        if changed_at_str:
            changed_at = datetime.fromisoformat(changed_at_str)
            age_hours  = (datetime.utcnow() - changed_at).total_seconds() / 3600
            if age_hours < PASSWORD_MIN_AGE_HOURS:
                hours_left = int(PASSWORD_MIN_AGE_HOURS - age_hours) + 1
                return jsonify({"error": f"Password is too new. Please wait {hours_left} more hour(s) before changing again."}), 400

        # Basic strength validation
        err = _validate_new_password(new_pw)
        if err:
            return jsonify({"error": err}), 400

        # #10 Prevent password re-use
        history = user.get("password_history", [user["password"]])
        for old_hash in history[-PASSWORD_HISTORY_DEPTH:]:
            if check_pw(new_pw, old_hash):
                return jsonify({"error": f"New password cannot be the same as any of your last {PASSWORD_HISTORY_DEPTH} passwords."}), 400

        new_hash    = hash_pw(new_pw)
        new_history = (history + [new_hash])[-PASSWORD_HISTORY_DEPTH:]
        now_iso     = datetime.utcnow().isoformat()

        users_col.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {
                "password":            new_hash,
                "password_changed_at": now_iso,
                "password_history":    new_history,
            }}
        )
        log_action(user_id, "CHANGE_PASSWORD", "Password changed successfully")
        return jsonify({"message": "Password changed successfully."})

    except Exception as e:
        log_action("system", "CHANGE_PASSWORD_ERROR", str(e))
        return jsonify({"error": "An error occurred. Please try again."}), 500


# Frontend
@app.route("/")
def index():
    return send_from_directory("frontend", "index.html")

if __name__ == "__main__": #remove before submission
    seed_defaults()
    print("\n🚀  HR System running → http://localhost:5000")
    print("─────────────────────────────────────────")
    print("  admin    / admin123     → Admin")
    print("  hr_staff / hr123        → HR Staff")
    print("  john_doe / employee123  → Employee")
    print("─────────────────────────────────────────\n")
    app.run(debug=True, port=5000) #change to false before submission