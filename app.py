from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    send_file
)

import sqlite3
import hashlib
import hmac
import secrets
import io
import os

from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import qrcode

from werkzeug.utils import secure_filename


# ============================================================
# CONFIGURATION
# ============================================================

app = Flask(__name__)

app.secret_key = os.environ.get(
    "FLASK_SECRET",
    "cryptopresence-secret-2026"
)

DB = "attendance.db"

UPLOAD_FOLDER = os.path.join("static", "materials")
ALLOWED_MATERIAL_EXTENSIONS = {
    "pdf", "ppt", "pptx", "doc", "docx", "txt", "zip"
}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

MASTER_SECRET = os.environ.get(
    "MASTER_SECRET",
    "cryptopresence-master-secret-2026"
).encode()


# ============================================================
# DATABASE
# ============================================================

def get_db():
    connection = sqlite3.connect(DB)
    connection.row_factory = sqlite3.Row
    return connection


# ============================================================
# PASSWORD HASHING
# ============================================================

def hash_password(password):
    return hashlib.sha256(
        password.encode()
    ).hexdigest()


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def init_db():

    connection = get_db()

    connection.executescript("""

        CREATE TABLE IF NOT EXISTS users (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            name TEXT NOT NULL,

            username TEXT UNIQUE NOT NULL,

            password_hash TEXT NOT NULL,

            role TEXT NOT NULL,

            faculty_username TEXT

        );


        CREATE TABLE IF NOT EXISTS sessions (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            course TEXT NOT NULL,

            room TEXT NOT NULL,

            nonce TEXT NOT NULL,

            created_at TEXT NOT NULL,

            expires_at TEXT NOT NULL,

            faculty_username TEXT NOT NULL

        );


        CREATE TABLE IF NOT EXISTS attendance (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            session_id INTEGER NOT NULL,

            student_id TEXT NOT NULL,

            timestamp TEXT NOT NULL,

            proof TEXT NOT NULL,

            previous_hash TEXT NOT NULL,

            record_hash TEXT NOT NULL,

            UNIQUE(session_id, student_id)

        );


        CREATE TABLE IF NOT EXISTS materials (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            title TEXT NOT NULL,

            description TEXT,

            filename TEXT NOT NULL,

            stored_filename TEXT NOT NULL,

            file_hash TEXT NOT NULL,

            uploaded_at TEXT NOT NULL,

            faculty_username TEXT NOT NULL

        );

    """)


    # ========================================================
    # THREE ADMINS
    # ========================================================

    admins = [

        (
            "Nikhil",
            "Nikhil",
            "nikhil143"
        ),

        (
            "Saketh",
            "saketh",
            "saketh123"
        ),

        (
            "Sai Charan",
            "sai_charan",
            "lizard143"
        )

    ]


    for name, username, password in admins:

        connection.execute(
            """
            INSERT OR IGNORE INTO users
            (
                name,
                username,
                password_hash,
                role
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                name,
                username,
                hash_password(password),
                "admin"
            )
        )


    # ========================================================
    # FACULTY
    # ========================================================

    connection.execute(
        """
        INSERT OR IGNORE INTO users
        (
            name,
            username,
            password_hash,
            role
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            "Nithisha",
            "Nithisha",
            hash_password("faculty@good"),
            "faculty"
        )
    )


    # ========================================================
    # 30 STUDENTS
    # ========================================================

    for number in range(1, 31):

        student_id = (
            f"23AIML{number:03d}"
        )

        student_name = (
            f"Student {number:02d}"
        )

        # Student login password format:
        # 23AIML001 -> student01@123
        # 23AIML002 -> student02@123
        # ...
        # 23AIML030 -> student30@123
        student_password = (
            f"student{number:02d}@123"
        )

        # Create the student if it does not exist.
        connection.execute(
            """
            INSERT OR IGNORE INTO users
            (name, username, password_hash, role, faculty_username)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                student_name,
                student_id,
                hash_password(student_password),
                "student",
                "Nithisha"
            )
        )

        # IMPORTANT: Always update existing student credentials.
        # This preserves attendance/material records while making
        # the new password take effect immediately.
        connection.execute(
            """
            UPDATE users
            SET name = ?,
                password_hash = ?,
                role = 'student',
                faculty_username = ?
            WHERE username = ?
            """,
            (
                student_name,
                hash_password(student_password),
                "Nithisha",
                student_id
            )
        )


    connection.commit()

    connection.close()


# ============================================================
# CRYPTOGRAPHIC SESSION SIGNATURE
# ============================================================

def create_session_signature(
    session_id,
    nonce,
    expires_at
):

    message = (
        f"{session_id}|"
        f"{nonce}|"
        f"{expires_at}"
    ).encode()

    return hmac.new(
        MASTER_SECRET,
        message,
        hashlib.sha256
    ).hexdigest()


# ============================================================
# ATTENDANCE HASH
# ============================================================

def create_record_hash(
    session_id,
    student_id,
    timestamp,
    proof,
    previous_hash
):

    message = (
        f"{session_id}|"
        f"{student_id}|"
        f"{timestamp}|"
        f"{proof}|"
        f"{previous_hash}"
    ).encode()

    return hashlib.sha256(
        message
    ).hexdigest()


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    connection = get_db()

    total_proofs = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM attendance
        """
    ).fetchone()["count"]

    total_students = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM users
        WHERE role = 'student'
        """
    ).fetchone()["count"]

    total_faculty = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM users
        WHERE role = 'faculty'
        """
    ).fetchone()["count"]

    total_sessions = connection.execute(
        """
        SELECT COUNT(*) AS count
        FROM sessions
        """
    ).fetchone()["count"]

    connection.close()

    stats = {

        "proofs": total_proofs,

        "students": total_students,

        "faculty": total_faculty,

        "sessions": total_sessions

    }

    return render_template(
        "home.html",
        stats=stats
    )


# ============================================================
# LOGIN
# ============================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        connection = get_db()

        user = connection.execute(
            """
            SELECT *
            FROM users
            WHERE username = ?
            AND password_hash = ?
            """,
            (
                username,
                hash_password(password)
            )
        ).fetchone()

        connection.close()


        if user:

            session.clear()

            session["user_id"] = user["id"]

            session["username"] = (
                user["username"]
            )

            session["name"] = (
                user["name"]
            )

            session["role"] = (
                user["role"]
            )

            return redirect(
                url_for("dashboard")
            )


        flash(
            "Invalid username or password.",
            "danger"
        )


    return render_template(
        "login.html"
    )


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("home")
    )


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
def dashboard():

    if "username" not in session:
        return redirect(url_for("login"))

    role = session["role"]
    connection = get_db()

    if role in ["admin", "faculty"]:

        if role == "faculty":
            students = connection.execute("""
                SELECT * FROM users
                WHERE role = 'student'
                AND faculty_username = ?
                ORDER BY username
            """, (session["username"],)).fetchall()

            attendance_rows = connection.execute("""
                SELECT a.*, s.course, s.room
                FROM attendance a
                JOIN sessions s ON s.id = a.session_id
                WHERE s.faculty_username = ?
                ORDER BY a.id DESC
                LIMIT 100
            """, (session["username"],)).fetchall()

            total_attendance = connection.execute("""
                SELECT COUNT(*) AS count
                FROM attendance a
                JOIN sessions s ON s.id = a.session_id
                WHERE s.faculty_username = ?
            """, (session["username"],)).fetchone()["count"]

            total_sessions = connection.execute("""
                SELECT COUNT(*) AS count
                FROM sessions
                WHERE faculty_username = ?
            """, (session["username"],)).fetchone()["count"]

        else:
            students = connection.execute("""
                SELECT * FROM users
                WHERE role = 'student'
                ORDER BY username
            """).fetchall()

            attendance_rows = connection.execute("""
                SELECT a.*, s.course, s.room
                FROM attendance a
                JOIN sessions s ON s.id = a.session_id
                ORDER BY a.id DESC
                LIMIT 100
            """).fetchall()

            total_attendance = connection.execute("""
                SELECT COUNT(*) AS count FROM attendance
            """).fetchone()["count"]

            total_sessions = connection.execute("""
                SELECT COUNT(*) AS count FROM sessions
            """).fetchone()["count"]

        unique_students = len(set(row["student_id"] for row in attendance_rows))

        student_analytics = []
        for student in students:
            student_id = student["username"]
            present_count = sum(1 for row in attendance_rows if row["student_id"] == student_id)
            percentage = round((present_count / total_sessions) * 100, 1) if total_sessions > 0 else 0

            if percentage >= 75:
                status = "Good"
            elif percentage >= 50:
                status = "Average"
            else:
                status = "Low"

            student_analytics.append({
                "id": student_id,
                "name": student["name"],
                "present": present_count,
                "total": total_sessions,
                "percentage": percentage,
                "status": status
            })

        good_count = sum(1 for item in student_analytics if item["percentage"] >= 75)
        average_count = sum(1 for item in student_analytics if 50 <= item["percentage"] < 75)
        low_count = sum(1 for item in student_analytics if item["percentage"] < 50)

        class_percentage = round(
            sum(item["percentage"] for item in student_analytics) / len(student_analytics), 1
        ) if student_analytics else 0

        if role == "faculty":
            course_rows = connection.execute("""
                SELECT s.course, COUNT(a.id) AS attendance_count
                FROM sessions s
                LEFT JOIN attendance a ON a.session_id = s.id
                WHERE s.faculty_username = ?
                GROUP BY s.course
                ORDER BY attendance_count DESC
            """, (session["username"],)).fetchall()

            recent_sessions = connection.execute("""
                SELECT s.*, COUNT(a.id) AS attendance_count
                FROM sessions s
                LEFT JOIN attendance a ON a.session_id = s.id
                WHERE s.faculty_username = ?
                GROUP BY s.id
                ORDER BY s.id DESC
                LIMIT 20
            """, (session["username"],)).fetchall()
        else:
            course_rows = connection.execute("""
                SELECT s.course, COUNT(a.id) AS attendance_count
                FROM sessions s
                LEFT JOIN attendance a ON a.session_id = s.id
                GROUP BY s.course
                ORDER BY attendance_count DESC
            """).fetchall()

            recent_sessions = connection.execute("""
                SELECT s.*, COUNT(a.id) AS attendance_count
                FROM sessions s
                LEFT JOIN attendance a ON a.session_id = s.id
                GROUP BY s.id
                ORDER BY s.id DESC
                LIMIT 20
            """).fetchall()

        connection.close()

        return render_template(
            "dashboard.html",
            role=role,
            students=students,
            rows=attendance_rows,
            total=total_attendance,
            unique=unique_students,
            sessions=recent_sessions,
            student_count=len(students),
            session_count=total_sessions,
            student_analytics=student_analytics,
            course_rows=course_rows,
            good_count=good_count,
            average_count=average_count,
            low_count=low_count,
            class_percentage=class_percentage
        )

    student = connection.execute("""
        SELECT * FROM users WHERE username = ?
    """, (session["username"],)).fetchone()

    attendance_rows = connection.execute("""
        SELECT a.*, s.course, s.room
        FROM attendance a
        JOIN sessions s ON s.id = a.session_id
        WHERE a.student_id = ?
        ORDER BY a.id DESC
    """, (session["username"],)).fetchall()

    total_sessions = connection.execute("""
        SELECT COUNT(*) AS count FROM sessions
    """).fetchone()["count"]

    present_count = connection.execute("""
        SELECT COUNT(*) AS count
        FROM attendance
        WHERE student_id = ?
    """, (session["username"],)).fetchone()["count"]

    connection.close()

    percentage = round((present_count / total_sessions) * 100, 1) if total_sessions > 0 else 0

    return render_template(
        "student_dashboard.html",
        student=student,
        rows=attendance_rows,
        total=total_sessions,
        present=present_count,
        percentage=percentage
    )


# ============================================================
# CREATE ATTENDANCE SESSION
# ============================================================

@app.route(
    "/create-session",
    methods=["POST"]
)
def create_session():

    if session.get("role") not in [
        "admin",
        "faculty"
    ]:

        return "Unauthorized", 403


    course = request.form.get(
        "course",
        ""
    ).strip()

    room = request.form.get(
        "room",
        ""
    ).strip()


    try:

        minutes = int(
            request.form.get(
                "minutes",
                "5"
            )
        )

    except ValueError:

        minutes = 5


    minutes = max(
        1,
        min(minutes, 30)
    )


    now = datetime.now(
        timezone.utc
    )

    expires = (
        now +
        timedelta(
            minutes=minutes
        )
    )


    nonce = secrets.token_urlsafe(
        24
    )


    connection = get_db()


    cursor = connection.execute(
        """
        INSERT INTO sessions
        (
            course,
            room,
            nonce,
            created_at,
            expires_at,
            faculty_username
        )

        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            course,
            room,
            nonce,
            now.isoformat(),
            expires.isoformat(),
            session["username"]
        )
    )


    session_id = cursor.lastrowid

    connection.commit()

    connection.close()


    return redirect(
        url_for(
            "qr_page",
            session_id=session_id
        )
    )


# ============================================================
# CREATE QR PAYLOAD
# ============================================================

def create_qr_payload(
    attendance_session
):

    signature = create_session_signature(
        attendance_session["id"],
        attendance_session["nonce"],
        attendance_session["expires_at"]
    )


    # IMPORTANT:
    # urlencode prevents + and : in the timestamp
    # from breaking the cryptographic token.

    parameters = urlencode({

        "nonce":
            attendance_session["nonce"],

        "exp":
            attendance_session["expires_at"],

        "sig":
            signature

    })


    return (
        f"{request.host_url}"
        f"mark/{attendance_session['id']}"
        f"?{parameters}"
    )


# ============================================================
# QR PAGE
# ============================================================

@app.route(
    "/session/<int:session_id>/qr"
)
def qr_page(session_id):

    connection = get_db()

    attendance_session = connection.execute(
        """
        SELECT *
        FROM sessions
        WHERE id = ?
        """,
        (
            session_id,
        )
    ).fetchone()

    connection.close()


    if not attendance_session:

        return "Session not found", 404


    return render_template(
        "qr.html",
        s=attendance_session
    )


# ============================================================
# QR IMAGE
# ============================================================

@app.route(
    "/session/<int:session_id>/qr.png"
)
def qr_png(session_id):

    connection = get_db()

    attendance_session = connection.execute(
        """
        SELECT *
        FROM sessions
        WHERE id = ?
        """,
        (
            session_id,
        )
    ).fetchone()

    connection.close()


    if not attendance_session:

        return "Session not found", 404


    payload = create_qr_payload(
        attendance_session
    )


    qr_image = qrcode.make(
        payload
    )


    buffer = io.BytesIO()

    qr_image.save(
        buffer,
        format="PNG"
    )

    buffer.seek(0)


    return send_file(
        buffer,
        mimetype="image/png"
    )


# ============================================================
# MARK ATTENDANCE
# ============================================================

@app.route(
    "/mark/<int:session_id>",
    methods=["GET", "POST"]
)
def mark(session_id):

    connection = get_db()

    attendance_session = connection.execute(
        """
        SELECT *
        FROM sessions
        WHERE id = ?
        """,
        (
            session_id,
        )
    ).fetchone()

    connection.close()


    if not attendance_session:

        return "Session not found", 404


    nonce = request.args.get(
        "nonce",
        ""
    )

    expiry = request.args.get(
        "exp",
        ""
    )

    received_signature = request.args.get(
        "sig",
        ""
    )


    expected_signature = (
        create_session_signature(
            attendance_session["id"],
            nonce,
            expiry
        )
    )


    signature_valid = hmac.compare_digest(
        received_signature,
        expected_signature
    )


    nonce_valid = (
        nonce ==
        attendance_session["nonce"]
    )


    expiry_valid = (
        expiry ==
        attendance_session["expires_at"]
    )


    try:

        expiry_time = datetime.fromisoformat(
            expiry
        )

        expired = (
            datetime.now(timezone.utc)
            >
            expiry_time
        )

    except Exception:

        expired = True


    token_valid = (

        signature_valid

        and nonce_valid

        and expiry_valid

        and not expired

    )


    if not token_valid:

        return render_template(
            "error.html",
            message=(
                "Invalid or expired "
                "cryptographic attendance token."
            )
        ), 403


    # ========================================================
    # POST ATTENDANCE
    # ========================================================

    if request.method == "POST":

        student_id = request.form.get(
            "student_id",
            ""
        ).strip().upper()


        if not student_id:

            return render_template(
                "error.html",
                message="Student ID is required."
            ), 400


        connection = get_db()


        # Make sure student exists
        student = connection.execute(
            """
            SELECT *
            FROM users

            WHERE username = ?

            AND role = 'student'
            """,
            (
                student_id,
            )
        ).fetchone()


        if not student:

            connection.close()

            return render_template(
                "error.html",
                message="Student account not found."
            ), 404


        # ====================================================
        # CHECK FACULTY ASSIGNMENT
        # ====================================================

        if (
            student["faculty_username"]
            !=
            attendance_session[
                "faculty_username"
            ]
        ):

            connection.close()

            return render_template(
                "error.html",
                message=(
                    "This student is not "
                    "assigned to this faculty."
                )
            ), 403


        # ====================================================
        # DUPLICATE CHECK
        # ====================================================

        existing = connection.execute(
            """
            SELECT id
            FROM attendance

            WHERE session_id = ?

            AND student_id = ?
            """,
            (
                session_id,
                student_id
            )
        ).fetchone()


        if existing:

            connection.close()

            return render_template(
                "error.html",
                message=(
                    "Attendance already "
                    "recorded for this student."
                )
            ), 409


        # ====================================================
        # CRYPTOGRAPHIC PROOF
        # ====================================================

        timestamp = datetime.now(
            timezone.utc
        ).isoformat()


        proof_message = (
            f"{attendance_session['id']}|"
            f"{student_id}|"
            f"{timestamp}|"
            f"{nonce}"
        ).encode()


        proof = hmac.new(
            MASTER_SECRET,
            proof_message,
            hashlib.sha256
        ).hexdigest()


        # ====================================================
        # PREVIOUS HASH
        # ====================================================

        previous_record = connection.execute(
            """
            SELECT record_hash
            FROM attendance

            ORDER BY id DESC

            LIMIT 1
            """
        ).fetchone()


        if previous_record:

            previous_hash = (
                previous_record["record_hash"]
            )

        else:

            previous_hash = "GENESIS"


        # ====================================================
        # CURRENT HASH
        # ====================================================

        current_hash = create_record_hash(
            attendance_session["id"],
            student_id,
            timestamp,
            proof,
            previous_hash
        )


        # ====================================================
        # SAVE ATTENDANCE
        # ====================================================

        connection.execute(
            """
            INSERT INTO attendance
            (
                session_id,
                student_id,
                timestamp,
                proof,
                previous_hash,
                record_hash
            )

            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                student_id,
                timestamp,
                proof,
                previous_hash,
                current_hash
            )
        )


        connection.commit()

        connection.close()


        return render_template(
            "success.html",

            student=student,

            s=attendance_session,

            hash=current_hash
        )


    return render_template(
        "mark.html",
        s=attendance_session
    )


# ============================================================
# ATTENDANCE RECORDS
# ============================================================


# ============================================================
# STUDY MATERIAL HELPERS
# ============================================================

def allowed_material_file(filename):

    return (
        bool(filename)
        and "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in ALLOWED_MATERIAL_EXTENSIONS
    )


def calculate_file_hash(filepath):

    sha256 = hashlib.sha256()

    with open(filepath, "rb") as file:

        for chunk in iter(
            lambda: file.read(1024 * 1024),
            b""
        ):
            sha256.update(chunk)

    return sha256.hexdigest()


# ============================================================
# STUDY MATERIALS - FACULTY UPLOAD
# ============================================================

@app.route("/materials/upload", methods=["POST"])
def upload_material():

    if "username" not in session:
        return redirect(url_for("login"))

    if session.get("role") not in ["faculty", "admin"]:
        flash("Only faculty or admin can upload materials.", "error")
        return redirect(url_for("dashboard"))

    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    uploaded_file = request.files.get("material")

    if not title:
        flash("Material title is required.", "error")
        return redirect(url_for("materials"))

    if not uploaded_file or not uploaded_file.filename:
        flash("Please select a file to upload.", "error")
        return redirect(url_for("materials"))

    original_filename = secure_filename(
        uploaded_file.filename
    )

    if not allowed_material_file(original_filename):
        flash(
            "Allowed files: PDF, PPT, PPTX, DOC, DOCX, TXT and ZIP.",
            "error"
        )
        return redirect(url_for("materials"))

    extension = original_filename.rsplit(".", 1)[1].lower()
    unique_name = (
        f"{secrets.token_hex(12)}.{extension}"
    )

    filepath = os.path.join(
        UPLOAD_FOLDER,
        unique_name
    )

    uploaded_file.save(filepath)

    file_hash = calculate_file_hash(filepath)

    connection = get_db()

    connection.execute(
        """
        INSERT INTO materials
        (
            title,
            description,
            filename,
            stored_filename,
            file_hash,
            uploaded_at,
            faculty_username
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            title,
            description,
            original_filename,
            unique_name,
            file_hash,
            datetime.now(timezone.utc).isoformat(),
            session["username"]
        )
    )

    connection.commit()
    connection.close()

    flash(
        "Study material uploaded and SHA-256 fingerprint generated.",
        "success"
    )

    return redirect(url_for("materials"))


# ============================================================
# STUDY MATERIALS - LIBRARY
# ============================================================

@app.route("/materials")
def materials():

    if "username" not in session:
        return redirect(url_for("login"))

    role = session.get("role")
    username = session.get("username")

    connection = get_db()

    if role == "student":

        student = connection.execute(
            """
            SELECT faculty_username
            FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()

        faculty_username = (
            student["faculty_username"]
            if student else None
        )

        materials_rows = connection.execute(
            """
            SELECT *
            FROM materials
            WHERE faculty_username = ?
            ORDER BY id DESC
            """,
            (faculty_username,)
        ).fetchall()

    elif role == "faculty":

        materials_rows = connection.execute(
            """
            SELECT *
            FROM materials
            WHERE faculty_username = ?
            ORDER BY id DESC
            """,
            (username,)
        ).fetchall()

    elif role == "admin":

        materials_rows = connection.execute(
            """
            SELECT *
            FROM materials
            ORDER BY id DESC
            """
        ).fetchall()

    else:

        materials_rows = []

    connection.close()

    return render_template(
        "materials.html",
        materials=materials_rows,
        role=role
    )


# ============================================================
# STUDY MATERIALS - DOWNLOAD
# ============================================================

@app.route("/materials/download/<int:material_id>")
def download_material(material_id):

    if "username" not in session:
        return redirect(url_for("login"))

    role = session.get("role")
    username = session.get("username")

    connection = get_db()

    material = connection.execute(
        """
        SELECT *
        FROM materials
        WHERE id = ?
        """,
        (material_id,)
    ).fetchone()

    if not material:
        connection.close()
        flash("Material not found.", "error")
        return redirect(url_for("materials"))

    allowed = role == "admin"

    if role == "faculty":
        allowed = (
            material["faculty_username"] == username
        )

    if role == "student":

        student = connection.execute(
            """
            SELECT faculty_username
            FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()

        allowed = (
            student is not None
            and material["faculty_username"]
            == student["faculty_username"]
        )

    connection.close()

    if not allowed:
        flash("You are not authorized to access this material.", "error")
        return redirect(url_for("materials"))

    filepath = os.path.join(
        UPLOAD_FOLDER,
        material["stored_filename"]
    )

    if not os.path.isfile(filepath):
        flash(
            "The material file is no longer available on the server.",
            "error"
        )
        return redirect(url_for("materials"))

    return send_file(
        filepath,
        as_attachment=True,
        download_name=material["filename"]
    )


# ============================================================
# STUDY MATERIALS - INTEGRITY VERIFICATION
# ============================================================

@app.route("/materials/verify/<int:material_id>")
def verify_material(material_id):

    if "username" not in session:
        return redirect(url_for("login"))

    role = session.get("role")
    username = session.get("username")

    connection = get_db()

    material = connection.execute(
        """
        SELECT *
        FROM materials
        WHERE id = ?
        """,
        (material_id,)
    ).fetchone()

    if not material:
        connection.close()
        flash("Material not found.", "error")
        return redirect(url_for("materials"))

    allowed = role == "admin"

    if role == "faculty":
        allowed = (
            material["faculty_username"] == username
        )

    if role == "student":

        student = connection.execute(
            """
            SELECT faculty_username
            FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()

        allowed = (
            student is not None
            and material["faculty_username"]
            == student["faculty_username"]
        )

    connection.close()

    if not allowed:
        flash("You are not authorized to verify this material.", "error")
        return redirect(url_for("materials"))

    filepath = os.path.join(
        UPLOAD_FOLDER,
        material["stored_filename"]
    )

    if not os.path.isfile(filepath):
        flash(
            "The material file is missing from the server.",
            "error"
        )
        return redirect(url_for("materials"))

    current_hash = calculate_file_hash(filepath)

    verified = hmac.compare_digest(
        current_hash,
        material["file_hash"]
    )

    return render_template(
        "material_verify.html",
        material=material,
        current_hash=current_hash,
        verified=verified
    )


# ============================================================
# STUDY MATERIALS - DELETE
# ============================================================

@app.route("/materials/delete/<int:material_id>", methods=["POST"])
def delete_material(material_id):

    if "username" not in session:
        return redirect(url_for("login"))

    role = session.get("role")
    username = session.get("username")

    if role not in ["faculty", "admin"]:
        flash("Only faculty or admin can delete materials.", "error")
        return redirect(url_for("materials"))

    connection = get_db()

    material = connection.execute(
        """
        SELECT *
        FROM materials
        WHERE id = ?
        """,
        (material_id,)
    ).fetchone()

    if not material:
        connection.close()
        flash("Material not found.", "error")
        return redirect(url_for("materials"))

    if (
        role == "faculty"
        and material["faculty_username"] != username
    ):
        connection.close()
        flash("You can only delete your own materials.", "error")
        return redirect(url_for("materials"))

    filepath = os.path.join(
        UPLOAD_FOLDER,
        material["stored_filename"]
    )

    connection.execute(
        """
        DELETE FROM materials
        WHERE id = ?
        """,
        (material_id,)
    )

    connection.commit()
    connection.close()

    if os.path.isfile(filepath):
        os.remove(filepath)

    flash("Study material deleted successfully.", "success")

    return redirect(url_for("materials"))


@app.route("/attendance")
def attendance():

    if "username" not in session:

        return redirect(
            url_for("login")
        )


    connection = get_db()


    if session["role"] == "student":

        rows = connection.execute(
            """
            SELECT
                a.*,
                s.course,
                s.room

            FROM attendance a

            JOIN sessions s
            ON s.id = a.session_id

            WHERE a.student_id = ?

            ORDER BY a.id DESC
            """,
            (
                session["username"],
            )
        ).fetchall()


    elif session["role"] == "faculty":

        rows = connection.execute(
            """
            SELECT
                a.*,
                s.course,
                s.room

            FROM attendance a

            JOIN sessions s
            ON s.id = a.session_id

            WHERE s.faculty_username = ?

            ORDER BY a.id DESC
            """,
            (
                session["username"],
            )
        ).fetchall()


    else:

        rows = connection.execute(
            """
            SELECT
                a.*,
                s.course,
                s.room

            FROM attendance a

            JOIN sessions s
            ON s.id = a.session_id

            ORDER BY a.id DESC
            """
        ).fetchall()


    connection.close()


    return render_template(
        "attendance.html",
        rows=rows
    )


# ============================================================
# INTEGRITY VERIFICATION
# ============================================================

@app.route("/verify")
def verify():

    if "username" not in session:

        return redirect(
            url_for("login")
        )


    connection = get_db()


    rows = connection.execute(
        """
        SELECT
            a.*,
            s.course

        FROM attendance a

        JOIN sessions s
        ON s.id = a.session_id

        ORDER BY a.id ASC
        """
    ).fetchall()


    connection.close()


    previous_hash = "GENESIS"

    checked_records = []

    chain_valid = True


    for record in rows:


        expected_hash = create_record_hash(
            record["session_id"],
            record["student_id"],
            record["timestamp"],
            record["proof"],
            record["previous_hash"]
        )


        previous_valid = (
            record["previous_hash"]
            ==
            previous_hash
        )


        hash_valid = hmac.compare_digest(
            record["record_hash"],
            expected_hash
        )


        record_valid = (
            previous_valid
            and hash_valid
        )


        checked_records.append(
            (
                record,
                record_valid
            )
        )


        if not record_valid:

            chain_valid = False


        previous_hash = (
            record["record_hash"]
        )


    return render_template(
        "verify.html",

        checked=checked_records,

        valid=chain_valid
    )


# ============================================================
# INITIALIZE DATABASE
# ============================================================
#
# IMPORTANT:
# This runs when Flask/Gunicorn imports the application.
# Therefore Render will also create the tables/users.
#

init_db()


# ============================================================
# LOCAL SERVER
# ============================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )