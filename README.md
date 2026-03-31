# HR Logging System — Flask + MongoDB

A full-stack HR management system with role-based access control.

## Roles
| Role | Access |
|------|--------|
| **Employee** | Attendance (time in/out), leave requests, payslips, profile |
| **HR Staff** | All employee tools + attendance monitor, leave approvals, reports |
| **Admin** | All HR tools + user management, payslip management, system logs |

---

## Setup & Run

### 1. Install Python dependencies
```bash
pip install -r requirements.txt
```

### 2. Start MongoDB
Make sure MongoDB is running locally on port 27017:
```bash
mongod
```
Or set a custom URI via environment variable:
```bash
export MONGO_URI="mongodb://localhost:27017/"
```

### 3. Run the app
```bash
python app.py
```
Visit → **http://localhost:5000**

---

## Default Accounts

| Username   | Password     | Role     |
|------------|--------------|----------|
| admin      | admin123     | Admin    |
| hr_staff   | hr123        | HR Staff |
| john_doe   | employee123  | Employee |
| jane_doe   | employee123  | Employee |

---

## Project Structure
```
hr_system/
├── app.py              ← Flask backend (MongoDB)
├── requirements.txt    ← Python dependencies
├── README.md
└── frontend/
    └── index.html      ← Single-page frontend (vanilla JS)
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/login | Authenticate |
| GET/POST | /api/users | List / create users |
| PUT/DELETE | /api/users/<id> | Update / delete user |
| POST | /api/attendance/timein | Clock in |
| POST | /api/attendance/timeout | Clock out |
| GET | /api/attendance/<user_id> | My attendance |
| GET | /api/attendance/all | All attendance (HR/Admin) |
| POST | /api/leave | Submit leave request |
| GET | /api/leave/<user_id> | My leave requests |
| GET | /api/leave/all | All leave requests (HR/Admin) |
| PUT | /api/leave/<id>/review | Approve/reject leave |
| GET/POST | /api/payslips | Payslip records |
| GET | /api/reports/summary | Summary stats |
| GET | /api/logs | System audit logs |
