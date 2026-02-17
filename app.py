from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
from datetime import datetime

app = Flask(__name__)
CORS(app, supports_credentials=True)


# CONFIG
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# DATABASE
def get_db():
    conn = sqlite3.connect("users.db", timeout=30)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()

    # USERS
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        phone TEXT,
        email TEXT UNIQUE,
        address TEXT,
        dob TEXT,
        gender TEXT,
        father_name TEXT,
        father_phone TEXT,
        mother_name TEXT,
        mother_phone TEXT,
        password TEXT,
        role TEXT DEFAULT 'USER'
    )
    """)

    # ACADEMICS (STEP 3)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS academics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE,
        school10 TEXT,
        board10 TEXT,
        year10 TEXT,
        cgpa10 TEXT,
        school12 TEXT,
        board12 TEXT,
        year12 TEXT,
        cgpa12 TEXT,
        course TEXT,
        prn TEXT,
        graduation_year TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    # DOCUMENTS
    cur.execute("""
    CREATE TABLE IF NOT EXISTS documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        doc_type TEXT,
        file_path TEXT,
        uploaded_at TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)


    # LEAVE REQUESTS
    cur.execute("""
CREATE TABLE IF NOT EXISTS leave_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    student_name TEXT,
    course_year TEXT,
    room_no TEXT,
    from_date TEXT,
    to_date TEXT,
    reason TEXT,
    leave_address TEXT,
    self_contact TEXT,
    parent_contact TEXT,
    guardian_contact TEXT,
    coming_date TEXT,
    remark TEXT,
    selected_admins TEXT,   -- 🔥 ADD THIS
    status TEXT DEFAULT 'PENDING',
    total_approvals INTEGER DEFAULT 0,
    created_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
)
""")


    # LEAVE APPROVALS
    cur.execute("""
    CREATE TABLE IF NOT EXISTS leave_approvals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        leave_id INTEGER,
        admin_id INTEGER,
        status TEXT,
        approved_at TEXT,
        FOREIGN KEY (leave_id) REFERENCES leave_requests(id),
        FOREIGN KEY (admin_id) REFERENCES users(id)
    )
    """)

    # NOTIFICATIONS
    cur.execute("""
    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        message TEXT,
        is_read INTEGER DEFAULT 0,
        created_at TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

        # ==============================
    # INSERT 4 FIXED ADMINS (IF NOT EXISTS)
    # ==============================

    fixed_admins = [
        ("Hostel Incharge", "9000000001", "InchargeHostel@pccoe.com"),
        ("Ms. Shivani Pandey", "9000000002", "shivani@pccoe.com"),
        ("Mr. Sandeep Patel", "9000000003", "sandeep@pccoe.com"),
        ("Ms. Rachana Ma'am", "9000000004", "rachana@pccoe.com"),
    ]

    for name, phone, email in fixed_admins:
        cur.execute("SELECT id FROM users WHERE email=?", (email,))
        if not cur.fetchone():
            cur.execute("""
                INSERT INTO users
                (name, phone, email, address, dob, gender,
                 father_name, father_phone, mother_name, mother_phone,
                 password, role)
                VALUES (?, ?, ?, '', '', '', '', '', '', '', ?, 'ADMIN')
            """, (
                name,
                phone,
                email,
                generate_password_hash("admin123")
            ))

    conn.commit()
    conn.close()

init_db()

# HELPERS

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# REGISTER (STEP 1 + STEP 3)

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    if not data:
        return jsonify({"message": "Invalid data"}), 400

    conn = get_db()
    cur = conn.cursor()

    try:
        # Email check
        cur.execute("SELECT 1 FROM users WHERE email=?", (data["email"],))
        if cur.fetchone():
            return jsonify({"message": "Email already exists"}), 409

        hashed_password = generate_password_hash(data["password"])

        # Insert user
        cur.execute("""
        INSERT INTO users
        (name, phone, email, address, dob, gender,
         father_name, father_phone, mother_name, mother_phone,
         password, role)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data["name"],
            data["phone"],
            data["email"],
            data["address"],
            data["dob"],
            data["gender"],
            data["father_name"],
            data["father_phone"],
            data["mother_name"],
            data["mother_phone"],
            hashed_password,
            "USER"
        ))

        user_id = cur.lastrowid

        # Insert academics
        acad = data.get("academics")
        if acad:
            cur.execute("""
            INSERT INTO academics
            (user_id, school10, board10, year10, cgpa10,
             school12, board12, year12, cgpa12,
             course, prn, graduation_year)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                user_id,
                acad["tenth"]["school"],
                acad["tenth"]["board"],
                acad["tenth"]["year"],
                acad["tenth"]["cgpa"],
                acad["twelfth"]["school"],
                acad["twelfth"]["board"],
                acad["twelfth"]["year"],
                acad["twelfth"]["cgpa"],
                acad["course"],
                acad["prn"],
                acad["graduation_year"]
            ))

        conn.commit()
        return jsonify({"message": "Registration Successful"}), 201

    except Exception as e:
        conn.rollback()
        return jsonify({"message": "Server error", "error": str(e)}), 500

    finally:
        conn.close()

# ==============================
# LOGIN
# ==============================
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    conn = get_db()
    cur = conn.cursor() 

    cur.execute("SELECT password, role FROM users WHERE email=?", (data["email"],))
    user = cur.fetchone()
    conn.close()

    if user and check_password_hash(user["password"], data["password"]):
        return jsonify({"status": "success", "role": user["role"]}), 200

    return jsonify({"status": "fail"}), 401

# ==============================
# UPLOAD DOCUMENT (STEP 2 + STEP 3)
# ==============================
@app.route("/upload-document", methods=["POST"])
def upload_document():
    email = request.form.get("email")
    doc_type = request.form.get("doc_type")
    file = request.files.get("file")

    if not all([email, doc_type, file]):
        return jsonify({"message": "Missing data"}), 400

    if not allowed_file(file.filename):
        return jsonify({"message": "Invalid file type"}), 400

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT id FROM users WHERE email=?", (email,))
    user = cur.fetchone()
    if not user:
        conn.close()
        return jsonify({"message": "User not found"}), 404

    # 🔥 REPLACE OLD DOCUMENT IF EXISTS
    cur.execute(
        "SELECT id, file_path FROM documents WHERE user_id=? AND doc_type=?",
        (user["id"], doc_type)
    )
    old = cur.fetchone()

    if old:
        if os.path.exists(old["file_path"]):
            os.remove(old["file_path"])
        cur.execute("DELETE FROM documents WHERE id=?", (old["id"],))

    filename = secure_filename(file.filename)
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    new_name = f"{user['id']}_{doc_type}_{timestamp}_{filename}"
    path = os.path.join(app.config["UPLOAD_FOLDER"], new_name)

    file.save(path)

    cur.execute("""
    INSERT INTO documents (user_id, doc_type, file_path, uploaded_at)
    VALUES (?, ?, ?, ?)
    """, (
        user["id"],
        doc_type,
        path,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()

    return jsonify({"message": "Document uploaded"}), 201

# ==============================
# GET USER PROFILE
# ==============================
@app.route("/get-user", methods=["POST"])
def get_user():
    email = request.json.get("email")
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
    SELECT name, phone, email, address, dob, gender,
           father_name, father_phone, mother_name, mother_phone
    FROM users WHERE email=?
    """, (email,))

    user = cur.fetchone()
    conn.close()

    if not user:
        return jsonify({"message": "User not found"}), 404

    return jsonify(dict(user))

# ==============================
# GET ACADEMICS
# ==============================
@app.route("/get-academics", methods=["POST"])
def get_academics():
    email = request.json.get("email")
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT id FROM users WHERE email=?", (email,))
    user = cur.fetchone()
    if not user:
        return jsonify({}), 404

    cur.execute("SELECT * FROM academics WHERE user_id=?", (user["id"],))
    acad = cur.fetchone()
    conn.close()

    return jsonify(dict(acad)) if acad else jsonify({})

# ==============================
# GET ALL DOCUMENTS
# ==============================
@app.route("/get-documents", methods=["POST"])
def get_documents():
    email = request.json.get("email")
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT id FROM users WHERE email=?", (email,))
    user = cur.fetchone()
    if not user:
        return jsonify([])

    cur.execute("""
    SELECT id, doc_type, uploaded_at
    FROM documents
    WHERE user_id=?
    ORDER BY uploaded_at DESC
    """, (user["id"],))

    docs = cur.fetchall()
    conn.close()

    return jsonify([
        {
            "id": d["id"],
            "doc_type": d["doc_type"],
            "uploaded_at": d["uploaded_at"]
        }
        for d in docs
    ])

# ==============================
# OPEN DOCUMENT
# ==============================
@app.route("/open-document/<int:doc_id>")
def open_document(doc_id):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT file_path FROM documents WHERE id=?", (doc_id,))
    doc = cur.fetchone()
    conn.close()

    if not doc:
        return "Not found", 404

    return send_file(doc["file_path"], as_attachment=False)

@app.route("/submit-leave", methods=["POST"])
def submit_leave():
    data = request.get_json()
    email = data.get("email")
    selected_admins = data.get("selected_admins")  # list of emails

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT id, name FROM users WHERE email=?", (email,))
    user = cur.fetchone()
    if not user:
        return jsonify({"message": "User not found"}), 404

    # Save leave request with selected admins
    cur.execute("""
    INSERT INTO leave_requests
    (user_id, student_name, course_year, room_no,
    from_date, to_date, reason, leave_address,
    self_contact, parent_contact, guardian_contact,
    coming_date, remark, selected_admins, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        user["id"],
        user["name"],
        data["course_year"],
        data["room_no"],
        data["from_date"],
        data["to_date"],
        data["reason"],
        data["leave_address"],
        data["self_contact"],
        data["parent_contact"],
        data["guardian_contact"],
        data["coming_date"],
        data["remark"],
        ",".join(data.get("selected_admins", [])),
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    leave_id = cur.lastrowid

    # 🔥 Notify ONLY selected admins
    for admin_email in selected_admins:
        cur.execute("SELECT id FROM users WHERE email=?", (admin_email,))
        admin = cur.fetchone()
        if admin:
            cur.execute("""
                INSERT INTO notifications (user_id, message, created_at)
                VALUES (?, ?, ?)
            """, (
                admin["id"],
                f"New leave request from {user['name']}",
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ))

    conn.commit()
    conn.close()

    return jsonify({"message": "Leave submitted successfully"})



@app.route("/get-leaves", methods=["GET"])
def get_leaves():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
    SELECT leave_requests.*, users.name
    FROM leave_requests
    JOIN users ON leave_requests.user_id = users.id
    ORDER BY created_at DESC
    """)

    leaves = cur.fetchall()
    conn.close()

    return jsonify([dict(l) for l in leaves])


@app.route("/get-notifications", methods=["POST"])
def get_notifications():
    email = request.json.get("email")

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT id FROM users WHERE email=?", (email,))
    user = cur.fetchone()
    if not user:
        return jsonify([])

    cur.execute("""
    SELECT id, message, created_at
    FROM notifications
    WHERE user_id=?
    ORDER BY created_at DESC
    """, (user["id"],))

    notes = cur.fetchall()
    conn.close()

    return jsonify([dict(n) for n in notes])

@app.route("/clear-notifications", methods=["POST"])
def clear_notifications():
    data = request.get_json()
    email = data.get("email")

    conn = get_db()
    cur = conn.cursor()

    # Get user
    cur.execute("SELECT id FROM users WHERE email=?", (email,))
    user = cur.fetchone()

    if not user:
        conn.close()
        return jsonify({"message": "User not found"}), 404

    # Delete all notifications of that user
    cur.execute("DELETE FROM notifications WHERE user_id=?", (user["id"],))

    conn.commit()
    conn.close()

    return jsonify({"message": "All notifications cleared"})

@app.route("/approve-leave", methods=["POST"])
def approve_leave():
    data = request.get_json()
    leave_id = data.get("leave_id")
    email = data.get("email")
    action = data.get("action")  # APPROVED or REJECTED

    conn = get_db()
    cur = conn.cursor()

    # ==============================
    # GET ADMIN
    # ==============================
    cur.execute("SELECT id, name FROM users WHERE email=? AND role='ADMIN'", (email,))
    admin = cur.fetchone()
    if not admin:
        conn.close()
        return jsonify({"message": "Unauthorized"}), 403

    admin_id = admin["id"]
    admin_name = admin["name"]

    # ==============================
    # CHECK LEAVE
    # ==============================
    cur.execute("""
        SELECT user_id, total_approvals, status, selected_admins
        FROM leave_requests
        WHERE id=?
    """, (leave_id,))
    leave = cur.fetchone()

    if not leave:
        conn.close()
        return jsonify({"message": "Leave not found"}), 404

    # 🚨 STOP if leave already finalized
    if leave["status"] in ["APPROVED", "REJECTED"]:
        conn.close()
        return jsonify({"message": "Leave already finalized"}), 400

    # 🚨 STOP if this admin was NOT selected
    selected_list = leave["selected_admins"].split(",")
    if email not in selected_list:
        conn.close()
        return jsonify({"message": "You are not selected for this leave approval"}), 403

    # 🚨 STOP if admin already responded
    cur.execute("""
        SELECT id FROM leave_approvals
        WHERE leave_id=? AND admin_id=?
    """, (leave_id, admin_id))

    if cur.fetchone():
        conn.close()
        return jsonify({"message": "You already responded"}), 400

    # ==============================
    # INSERT APPROVAL RECORD
    # ==============================
    cur.execute("""
        INSERT INTO leave_approvals (leave_id, admin_id, status, approved_at)
        VALUES (?, ?, ?, ?)
    """, (
        leave_id,
        admin_id,
        action,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    # ==============================
    # IF REJECTED
    # ==============================
    if action == "REJECTED":

        cur.execute("""
            UPDATE leave_requests
            SET status='REJECTED'
            WHERE id=?
        """, (leave_id,))

        cur.execute("""
            INSERT INTO notifications (user_id, message, created_at)
            VALUES (?, ?, ?)
        """, (
            leave["user_id"],
            f"Your leave request was rejected by {admin_name}.",
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))

    # ==============================
    # IF APPROVED
    # ==============================
    # IF APPROVED
    # ==============================
    else:
        # Insert approval already ho chuka hai

        # Count approvals again AFTER insert
        cur.execute("""
            SELECT COUNT(*) as total
            FROM leave_approvals
            WHERE leave_id=? AND status='APPROVED'
        """, (leave_id,))
        approved_count = cur.fetchone()["total"]

        required_count = len(selected_list)

        # Notify student for this approval
        cur.execute("""
            INSERT INTO notifications (user_id, message, created_at)
            VALUES (?, ?, ?)
        """, (
            leave["user_id"],
            f"Your leave request was approved by {admin_name}.",
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))

        # If all selected admins approved
        if approved_count >= required_count:

            cur.execute("""
                UPDATE leave_requests
                SET status='APPROVED'
                WHERE id=?
            """, (leave_id,))

            cur.execute("""
                INSERT INTO notifications (user_id, message, created_at)
                VALUES (?, ?, ?)
            """, (
                leave["user_id"],
                "Your leave request has been fully approved.",
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ))


    conn.commit()
    conn.close()

    return jsonify({"message": "Action completed"})

# ==============================
# ADMIN DASHBOARD STATS
# ==============================
@app.route("/admin-stats", methods=["GET"])
def admin_stats():
    conn = get_db()
    cur = conn.cursor()

    # Total users
    cur.execute("SELECT COUNT(*) as total FROM users WHERE role='USER'")
    total_users = cur.fetchone()["total"]

    # Total leaves
    cur.execute("SELECT COUNT(*) as total FROM leave_requests")
    total_leaves = cur.fetchone()["total"]

    # Pending leaves (not fully approved and not rejected)
    cur.execute("""
        SELECT COUNT(*) as total
        FROM leave_requests
        WHERE status='PENDING'
    """)
    pending = cur.fetchone()["total"]

    # Fully approved leaves
    cur.execute("""
        SELECT COUNT(*) as total
        FROM leave_requests
        WHERE status='APPROVED'
    """)
    approved = cur.fetchone()["total"]

    conn.close()

    return jsonify({
        "total_users": total_users,
        "total_leaves": total_leaves,
        "pending": pending,
        "approved": approved
    })

@app.route("/user-stats", methods=["POST"])
def user_stats():
    data = request.get_json()
    email = data.get("email")

    conn = get_db()
    cur = conn.cursor()

    # Get user id
    cur.execute("SELECT id FROM users WHERE email=?", (email,))
    user = cur.fetchone()

    if not user:
        conn.close()
        return jsonify({"message": "User not found"}), 404

    user_id = user["id"]

    # Total leaves of this user
    cur.execute("""
        SELECT COUNT(*) as total
        FROM leave_requests
        WHERE user_id=?
    """, (user_id,))
    total = cur.fetchone()["total"]

    # Approved leaves
    cur.execute("""
        SELECT COUNT(*) as total
        FROM leave_requests
        WHERE user_id=? AND status='APPROVED'
    """, (user_id,))
    approved = cur.fetchone()["total"]

    # Pending leaves
    cur.execute("""
        SELECT COUNT(*) as total
        FROM leave_requests
        WHERE user_id=? AND status='PENDING'
    """, (user_id,))
    pending = cur.fetchone()["total"]

    conn.close()

    return jsonify({
        "total": total,
        "approved": approved,
        "pending": pending
    })


# ==============================
# RUN
# ==============================
if __name__ == "__main__":
    app.run(debug=True)
