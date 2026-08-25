from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
import sqlite3, hashlib, hmac, secrets, io
from datetime import datetime, timedelta, timezone
import qrcode

app = Flask(__name__)
app.secret_key = "change-this-secret"
DB = "attendance.db"
MASTER_SECRET = b"change-this-demo-secret"

def get_db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    c = get_db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        course TEXT NOT NULL,
        room TEXT NOT NULL,
        nonce TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS attendance(
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
    for u,p,r in [
        ("admin","admin","admin"),
        ("faculty","faculty","faculty"),
        ("student","student","student")
    ]:
        c.execute("INSERT OR IGNORE INTO users(username,password,role) VALUES(?,?,?)",(u,p,r))
    c.commit(); c.close()

def session_signature(session_id, nonce, expires_at):
    msg = f"{session_id}|{nonce}|{expires_at}".encode()
    return hmac.new(MASTER_SECRET, msg, hashlib.sha256).hexdigest()

def record_hash(session_id, student_id, timestamp, proof, previous_hash):
    raw=f"{session_id}|{student_id}|{timestamp}|{proof}|{previous_hash}".encode()
    return hashlib.sha256(raw).hexdigest()

@app.route("/")
def home():
    c=get_db()
    count=c.execute("SELECT COUNT(*) n FROM attendance").fetchone()["n"]
    students=c.execute("SELECT COUNT(DISTINCT student_id) n FROM attendance").fetchone()["n"]
    sessions=c.execute("SELECT COUNT(*) n FROM sessions").fetchone()["n"]
    c.close()
    return render_template("home.html", count=count, students=students, sessions=sessions)

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        c=get_db()
        u=c.execute("SELECT * FROM users WHERE username=? AND password=?",
                    (request.form["username"], request.form["password"])).fetchone()
        c.close()
        if u:
            session["username"]=u["username"]; session["role"]=u["role"]
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.","danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

@app.route("/dashboard")
def dashboard():
    if "username" not in session: return redirect(url_for("login"))
    c=get_db()
    rows=c.execute("""SELECT a.*,s.course,s.room FROM attendance a
                     JOIN sessions s ON s.id=a.session_id
                     ORDER BY a.id DESC LIMIT 50""").fetchall()
    course_counts=c.execute("""SELECT s.course,COUNT(*) n FROM attendance a
                               JOIN sessions s ON s.id=a.session_id
                               GROUP BY s.course ORDER BY n DESC""").fetchall()
    active=c.execute("SELECT * FROM sessions ORDER BY id DESC LIMIT 8").fetchall()
    total=c.execute("SELECT COUNT(*) n FROM attendance").fetchone()["n"]
    students=c.execute("SELECT COUNT(DISTINCT student_id) n FROM attendance").fetchone()["n"]
    c.close()
    return render_template("dashboard.html",rows=rows,course_counts=course_counts,
                           active=active,total=total,students=students)

@app.route("/create-session", methods=["POST"])
def create_session():
    if session.get("role") not in ("admin","faculty"):
        return "Unauthorized",403
    course=request.form.get("course","").strip()
    room=request.form.get("room","").strip()
    minutes=int(request.form.get("minutes","5"))
    now=datetime.now(timezone.utc)
    expires=now+timedelta(minutes=max(1,min(minutes,30)))
    nonce=secrets.token_urlsafe(18)
    c=get_db()
    cur=c.execute("""INSERT INTO sessions(course,room,nonce,created_at,expires_at)
                     VALUES(?,?,?,?,?)""",
                  (course,room,nonce,now.isoformat(),expires.isoformat()))
    sid=cur.lastrowid
    c.commit(); c.close()
    return redirect(url_for("qr_page",session_id=sid))

@app.route("/session/<int:session_id>/qr")
def qr_page(session_id):
    c=get_db(); s=c.execute("SELECT * FROM sessions WHERE id=?",(session_id,)).fetchone(); c.close()
    if not s: return "Session not found",404
    sig=session_signature(s["id"],s["nonce"],s["expires_at"])
    payload=f"{request.host_url}mark/{s['id']}?nonce={s['nonce']}&exp={s['expires_at']}&sig={sig}"
    return render_template("qr.html",s=s,payload=payload)

@app.route("/session/<int:session_id>/qr.png")
def qr_png(session_id):
    c=get_db(); s=c.execute("SELECT * FROM sessions WHERE id=?",(session_id,)).fetchone(); c.close()
    if not s: return "Session not found",404
    sig=session_signature(s["id"],s["nonce"],s["expires_at"])
    payload=f"{request.host_url}mark/{s['id']}?nonce={s['nonce']}&exp={s['expires_at']}&sig={sig}"
    img=qrcode.make(payload); buf=io.BytesIO(); img.save(buf,"PNG"); buf.seek(0)
    return send_file(buf,mimetype="image/png")

@app.route("/mark/<int:session_id>", methods=["GET","POST"])
def mark(session_id):
    c=get_db(); s=c.execute("SELECT * FROM sessions WHERE id=?",(session_id,)).fetchone(); c.close()
    if not s: return "Session not found",404
    nonce=request.args.get("nonce",""); exp=request.args.get("exp",""); sig=request.args.get("sig","")
    valid=hmac.compare_digest(sig,session_signature(s["id"],nonce,exp)) and nonce==s["nonce"] and exp==s["expires_at"]
    try: expired=datetime.now(timezone.utc)>datetime.fromisoformat(exp)
    except: expired=True
    if not valid or expired:
        return render_template("error.html",message="Invalid or expired cryptographic attendance token."),403
    if request.method=="POST":
        student=request.form["student_id"].strip().upper()
        ts=datetime.now(timezone.utc).isoformat()
        proof=hmac.new(MASTER_SECRET,f"{s['id']}|{student}|{ts}|{nonce}".encode(),hashlib.sha256).hexdigest()
        c=get_db()
        if c.execute("SELECT id FROM attendance WHERE session_id=? AND student_id=?",(session_id,student)).fetchone():
            c.close(); return render_template("error.html",message="Attendance already recorded for this student."),409
        last=c.execute("SELECT record_hash FROM attendance ORDER BY id DESC LIMIT 1").fetchone()
        prev=last["record_hash"] if last else "GENESIS"
        rh=record_hash(session_id,student,ts,proof,prev)
        c.execute("""INSERT INTO attendance(session_id,student_id,timestamp,proof,previous_hash,record_hash)
                     VALUES(?,?,?,?,?,?)""",(session_id,student,ts,proof,prev,rh))
        c.commit(); c.close()
        return render_template("success.html",student=student,s=s,hash=rh)
    return render_template("mark.html",s=s)

@app.route("/verify")
def verify():
    c=get_db(); rows=c.execute("""SELECT a.*,s.course FROM attendance a JOIN sessions s ON s.id=a.session_id ORDER BY a.id""").fetchall(); c.close()
    prev="GENESIS"; checked=[]; valid=True
    for r in rows:
        ok=(r["previous_hash"]==prev and hmac.compare_digest(
            r["record_hash"],record_hash(r["session_id"],r["student_id"],r["timestamp"],r["proof"],r["previous_hash"])))
        checked.append((r,ok)); valid=valid and ok; prev=r["record_hash"]
    return render_template("verify.html",checked=checked,valid=valid)

@app.route("/attendance")
def attendance():
    c=get_db(); rows=c.execute("""SELECT a.*,s.course,s.room FROM attendance a
                                  JOIN sessions s ON s.id=a.session_id ORDER BY a.id DESC""").fetchall(); c.close()
    return render_template("attendance.html",rows=rows)

if __name__=="__main__":
    init_db()
    app.run(debug=True,host="127.0.0.1",port=5000)
