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

from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import qrcode


# =========================================================
# APPLICATION CONFIGURATION
# =========================================================

app = Flask(__name__)

app.secret_key = "change-this-secret-in-production"

DB = "attendance.db"

# Demo secret for cryptographic operations
# For real deployment, use an environment variable.
MASTER_SECRET = b"change-this-demo-secret"


# =========================================================
# DATABASE CONNECTION
# =========================================================

def get_db():
    connection = sqlite3.connect(DB)
    connection.row_factory = sqlite3.Row
    return connection


# =========================================================
# DATABASE INITIALIZATION
# =========================================================

def init_db():

    connection = get_db()

    connection.executescript("""
    
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        course TEXT NOT NULL,
        room TEXT NOT NULL,
        nonce TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL
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

    """)

    # Demo users
    demo_users = [
        ("admin", "admin", "admin"),
        ("faculty", "faculty", "faculty"),
        ("student", "student", "student")
    ]

    for username, password, role in demo_users:

        connection.execute(
            """
            INSERT OR IGNORE INTO users
            (username, password, role)
            VALUES (?, ?, ?)
            """,
            (username, password, role)
        )

    connection.commit()
    connection.close()


# =========================================================
# CRYPTOGRAPHIC SESSION SIGNATURE
# =========================================================

def session_signature(session_id, nonce, expires_at):

    message = (
        f"{session_id}|"
        f"{nonce}|"
        f"{expires_at}"
    ).encode()

    signature = hmac.new(
        MASTER_SECRET,
        message,
        hashlib.sha256
    ).hexdigest()

    return signature


# =========================================================
# ATTENDANCE RECORD HASH
# =========================================================

def create_record_hash(
    session_id,
    student_id,
    timestamp,
    proof,
    previous_hash
):

    data = (
        f"{session_id}|"
        f"{student_id}|"
        f"{timestamp}|"
        f"{proof}|"
        f"{previous_hash}"
    ).encode()

    return hashlib.sha256(data).hexdigest()


# =========================================================
# HOME PAGE
# =========================================================

@app.route("/")
def home():

    connection = get_db()

    total_attendance = connection.execute(
        "SELECT COUNT(*) AS n FROM attendance"
    ).fetchone()["n"]

    total_students = connection.execute(
        """
        SELECT COUNT(DISTINCT student_id) AS n
        FROM attendance
        """
    ).fetchone()["n"]

    total_sessions = connection.execute(
        "SELECT COUNT(*) AS n FROM sessions"
    ).fetchone()["n"]

    connection.close()

    return render_template(
        "home.html",
        count=total_attendance,
        students=total_students,
        sessions=total_sessions
    )


# =========================================================
# LOGIN
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        connection = get_db()

        user = connection.execute(
            """
            SELECT *
            FROM users
            WHERE username = ?
            AND password = ?
            """,
            (username, password)
        ).fetchone()

        connection.close()

        if user:

            session["username"] = user["username"]
            session["role"] = user["role"]

            return redirect(url_for("dashboard"))

        flash(
            "Invalid username or password.",
            "danger"
        )

    return render_template("login.html")


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("home"))


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
def dashboard():

    if "username" not in session:
        return redirect(url_for("login"))

    connection = get_db()

    # Recent attendance
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

        LIMIT 50
        """
    ).fetchall()

    # Course statistics
    course_counts = connection.execute(
        """
        SELECT
            s.course,
            COUNT(*) AS n

        FROM attendance a

        JOIN sessions s
        ON s.id = a.session_id

        GROUP BY s.course

        ORDER BY n DESC
        """
    ).fetchall()

    # Recent sessions
    active_sessions = connection.execute(
        """
        SELECT *
        FROM sessions
        ORDER BY id DESC
        LIMIT 8
        """
    ).fetchall()

    # Total attendance
    total = connection.execute(
        """
        SELECT COUNT(*) AS n
        FROM attendance
        """
    ).fetchone()["n"]

    # Unique students
    students = connection.execute(
        """
        SELECT COUNT(DISTINCT student_id) AS n
        FROM attendance
        """
    ).fetchone()["n"]

    connection.close()

    return render_template(
        "dashboard.html",
        rows=rows,
        course_counts=course_counts,
        active=active_sessions,
        total=total,
        students=students
    )


# =========================================================
# CREATE ATTENDANCE SESSION
# =========================================================

@app.route("/create-session", methods=["POST"])
def create_session():

    # Only admin/faculty can create sessions
    if session.get("role") not in ("admin", "faculty"):

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

    # Keep expiry between 1 and 30 minutes
    minutes = max(
        1,
        min(minutes, 30)
    )

    now = datetime.now(timezone.utc)

    expires = (
        now +
        timedelta(minutes=minutes)
    )

    # Generate secure random nonce
    nonce = secrets.token_urlsafe(18)

    connection = get_db()

    cursor = connection.execute(
        """
        INSERT INTO sessions
        (
            course,
            room,
            nonce,
            created_at,
            expires_at
        )

        VALUES (?, ?, ?, ?, ?)
        """,
        (
            course,
            room,
            nonce,
            now.isoformat(),
            expires.isoformat()
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


# =========================================================
# QR PAGE
# =========================================================

@app.route("/session/<int:session_id>/qr")
def qr_page(session_id):

    connection = get_db()

    attendance_session = connection.execute(
        """
        SELECT *
        FROM sessions
        WHERE id = ?
        """,
        (session_id,)
    ).fetchone()

    connection.close()

    if not attendance_session:

        return "Session not found", 404

    # Generate cryptographic signature
    signature = session_signature(
        attendance_session["id"],
        attendance_session["nonce"],
        attendance_session["expires_at"]
    )

    # IMPORTANT:
    # urlencode() protects +, :, etc. inside the expiry timestamp.
    parameters = urlencode(
        {
            "nonce": attendance_session["nonce"],
            "exp": attendance_session["expires_at"],
            "sig": signature
        }
    )

    payload = (
        f"{request.host_url}"
        f"mark/{attendance_session['id']}"
        f"?{parameters}"
    )

    return render_template(
        "qr.html",
        s=attendance_session,
        payload=payload
    )


# =========================================================
# QR IMAGE
# =========================================================

@app.route("/session/<int:session_id>/qr.png")
def qr_png(session_id):

    connection = get_db()

    attendance_session = connection.execute(
        """
        SELECT *
        FROM sessions
        WHERE id = ?
        """,
        (session_id,)
    ).fetchone()

    connection.close()

    if not attendance_session:

        return "Session not found", 404

    # Generate signature
    signature = session_signature(
        attendance_session["id"],
        attendance_session["nonce"],
        attendance_session["expires_at"]
    )

    # IMPORTANT QR FIX
    parameters = urlencode(
        {
            "nonce": attendance_session["nonce"],
            "exp": attendance_session["expires_at"],
            "sig": signature
        }
    )

    payload = (
        f"{request.host_url}"
        f"mark/{attendance_session['id']}"
        f"?{parameters}"
    )

    # Generate QR
    qr_image = qrcode.make(payload)

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


# =========================================================
# MARK ATTENDANCE
# =========================================================

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
        (session_id,)
    ).fetchone()

    connection.close()

    if not attendance_session:

        return "Session not found", 404

    # Get cryptographic parameters
    nonce = request.args.get(
        "nonce",
        ""
    )

    expiry = request.args.get(
        "exp",
        ""
    )

    signature = request.args.get(
        "sig",
        ""
    )

    # Generate expected signature
    expected_signature = session_signature(
        attendance_session["id"],
        nonce,
        expiry
    )

    # Compare signatures securely
    signature_valid = hmac.compare_digest(
        signature,
        expected_signature
    )

    # Make sure nonce belongs to this session
    nonce_valid = (
        nonce ==
        attendance_session["nonce"]
    )

    # Make sure expiry matches original expiry
    expiry_valid = (
        expiry ==
        attendance_session["expires_at"]
    )

    # Check expiration
    try:

        expiry_datetime = datetime.fromisoformat(
            expiry
        )

        expired = (
            datetime.now(timezone.utc)
            >
            expiry_datetime
        )

    except Exception:

        expired = True

    # Final cryptographic validation
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

    # =====================================================
    # POST - RECORD ATTENDANCE
    # =====================================================

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

        timestamp = datetime.now(
            timezone.utc
        ).isoformat()

        # Generate cryptographic attendance proof
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

        connection = get_db()

        # Prevent duplicate attendance
        already_exists = connection.execute(
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

        if already_exists:

            connection.close()

            return render_template(
                "error.html",
                message=(
                    "Attendance already recorded "
                    "for this student."
                )
            ), 409

        # Get previous hash
        last_record = connection.execute(
            """
            SELECT record_hash
            FROM attendance
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()

        if last_record:

            previous_hash = (
                last_record["record_hash"]
            )

        else:

            previous_hash = "GENESIS"

        # Generate current record hash
        current_hash = create_record_hash(
            attendance_session["id"],
            student_id,
            timestamp,
            proof,
            previous_hash
        )

        # Store attendance
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
            student=student_id,
            s=attendance_session,
            hash=current_hash
        )

    # GET request
    return render_template(
        "mark.html",
        s=attendance_session
    )


# =========================================================
# CRYPTOGRAPHIC INTEGRITY VERIFICATION
# =========================================================

@app.route("/verify")
def verify():

    connection = get_db()

    records = connection.execute(
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

    for record in records:

        expected_hash = create_record_hash(
            record["session_id"],
            record["student_id"],
            record["timestamp"],
            record["proof"],
            record["previous_hash"]
        )

        previous_link_valid = (
            record["previous_hash"]
            ==
            previous_hash
        )

        hash_valid = hmac.compare_digest(
            record["record_hash"],
            expected_hash
        )

        record_valid = (
            previous_link_valid
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


# =========================================================
# ATTENDANCE RECORDS
# =========================================================

@app.route("/attendance")
def attendance():

    connection = get_db()

    records = connection.execute(
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
        rows=records
    )


# =========================================================
# INITIALIZE DATABASE
# IMPORTANT FOR RENDER / GUNICORN
# =========================================================

init_db()


# =========================================================
# LOCAL DEVELOPMENT
# =========================================================

if __name__ == "__main__":

    app.run(
        debug=True,
        host="0.0.0.0",
        port=5000
    )