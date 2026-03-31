from flask import Flask, request, jsonify, send_from_directory
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from pymongo import MongoClient
from pymongo.server_api import ServerApi
from bson import ObjectId
from datetime import datetime
import hashlib
import os
from dotenv import load_dotenv
import bcrypt
import re

app = Flask(__name__, static_folder='frontend', static_url_path='')
CORS(app)

app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET", "super-secret-fallback-key")
jwt = JWTManager(app)

# ─── MongoDB CONNECTION ───────────────────────────────────────────────────────
uri = os.getenv("MONGO_DB_URI")
#MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
client = MongoClient(uri, server_api=ServerApi('1'))
db = client["hr_logging_system"]

users_col       = db["users"]
attendance_col  = db["attendance"]
leave_col       = db["leave_requests"]
payslips_col    = db["payslips"]
logs_col        = db["system_logs"]

# ─── HELPERS ──────────────────────────────────────────────────────────────────
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
        users_col.insert_many(defaults)
        print("✅  Seeded default users.")

# ─── AUTH ─────────────────────────────────────────────────────────────────────
@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    user = users_col.find_one({"username": data.get("username")})
    if not user or not check_pw(data.get("password", ""), user["password"]):
        return jsonify({"error": "Invalid credentials"}), 401
    log_action(str(user["_id"]), "LOGIN")
    access_token = create_access_token(identity=str(user["_id"]))
    return jsonify({
    "message": "Login successful",
    "token": access_token,
    "user": serialize({
        "_id": user["_id"],
        "username": user["username"],
        "full_name": user["full_name"],
        "role": user["role"],
        "department": user["department"],
        "email": user.get("email", "")
    })
})


# ─── USERS ────────────────────────────────────────────────────────────────────
@app.route("/api/users", methods=["GET"])
@jwt_required()
def get_users():
    users = list(users_col.find({}, {"password": 0}))
    return jsonify(serialize(users))

@app.route("/api/users", methods=["POST"])
@jwt_required()
def create_user():
    data = request.json
    if users_col.find_one({"username": data["username"]}):
        return jsonify({"error": "Username already exists"}), 400
    user = {
        "username":   data["username"],
        "password":   hash_pw(data["password"]),
        "full_name":  data["full_name"],
        "role":       data["role"],
        "department": data.get("department", "General"),
        "email":      data.get("email", ""),
        "created_at": datetime.utcnow().isoformat()
    }
    result = users_col.insert_one(user)
    log_action(data.get("admin_id", "system"), "CREATE_USER", data["username"])
    return jsonify({"message": "User created", "id": str(result.inserted_id)}), 201

@app.route("/api/users/<user_id>", methods=["PUT"])
@jwt_required()
def update_user(user_id):
    data = request.json
    update = {k: v for k, v in data.items() if k not in ("_id", "password")}
    if "new_password" in data:
        update["password"] = hash_pw(data["new_password"])
    users_col.update_one({"_id": ObjectId(user_id)}, {"$set": update})
    return jsonify({"message": "User updated"})

@app.route("/api/users/<user_id>", methods=["DELETE"])
@jwt_required()
def delete_user(user_id):
    users_col.delete_one({"_id": ObjectId(user_id)})
    return jsonify({"message": "User deleted"})

# ─── ATTENDANCE ───────────────────────────────────────────────────────────────
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
def get_all_attendance():
    records = list(attendance_col.find({}).sort("date", -1).limit(100))
    enriched = []
    for r in records:
        user = users_col.find_one({"_id": ObjectId(r["user_id"])}, {"full_name": 1, "department": 1}) if ObjectId.is_valid(r.get("user_id", "")) else None
        r["full_name"] = user["full_name"] if user else r["user_id"]
        r["department"] = user.get("department", "") if user else ""
        enriched.append(r)
    return jsonify(serialize(enriched))

# ─── LEAVE REQUESTS ───────────────────────────────────────────────────────────
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
def review_leave(leave_id):
    data = request.json
    leave_col.update_one({"_id": ObjectId(leave_id)}, {"$set": {
        "status": data["status"],
        "reviewed_by": data["reviewed_by"],
        "reviewed_at": datetime.utcnow().isoformat()
    }})
    log_action(data["reviewed_by"], "REVIEW_LEAVE", f"{leave_id}:{data['status']}")
    return jsonify({"message": f"Leave {data['status']}"})

# ─── PAYSLIPS ─────────────────────────────────────────────────────────────────
@app.route("/api/payslips/<user_id>", methods=["GET"])
@jwt_required()
def get_payslips(user_id):
    records = list(payslips_col.find({"user_id": user_id}).sort("period", -1))
    return jsonify(serialize(records))

@app.route("/api/payslips", methods=["POST"])
@jwt_required()
def add_payslip():
    data = request.json
    data["created_at"] = datetime.utcnow().isoformat()
    result = payslips_col.insert_one(data)
    return jsonify({"message": "Payslip added", "id": str(result.inserted_id)}), 201

# ─── REPORTS ──────────────────────────────────────────────────────────────────
@app.route("/api/reports/summary", methods=["GET"])
@jwt_required()
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

# ─── SYSTEM LOGS ──────────────────────────────────────────────────────────────
@app.route("/api/logs", methods=["GET"])
@jwt_required()
def get_logs():
    logs = list(logs_col.find({}).sort("timestamp", -1).limit(100))
    return jsonify(serialize(logs))

# ─── SERVE FRONTEND ───────────────────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory("frontend", "index.html")

if __name__ == "__main__":
    seed_defaults()
    print("\n🚀  HR System running → http://localhost:5000")
    print("─────────────────────────────────────────")
    print("  admin    / admin123     → Admin")
    print("  hr_staff / hr123        → HR Staff")
    print("  john_doe / employee123  → Employee")
    print("─────────────────────────────────────────\n")
    app.run(debug=True, port=5000)
