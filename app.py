from flask import Flask,render_template,request,redirect,url_for,session,flash,send_file
import sqlite3,hashlib,hmac,secrets,io,os,base64,uuid
from datetime import datetime,timedelta,timezone
from urllib.parse import urlencode
import qrcode

app=Flask(__name__); app.secret_key=os.environ.get("FLASK_SECRET","change-this-secret")
PHOTO_FOLDER="static/attendance_photos"; os.makedirs(PHOTO_FOLDER, exist_ok=True)
DB="attendance.db"; MASTER_SECRET=os.environ.get("MASTER_SECRET","change-this-demo-secret").encode()

def db():
 c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c
def hp(p): return hashlib.sha256(p.encode()).hexdigest()
def init_db():
 c=db()
 c.executescript("""CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,username TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL,faculty_username TEXT);
 CREATE TABLE IF NOT EXISTS sessions(id INTEGER PRIMARY KEY AUTOINCREMENT,course TEXT NOT NULL,room TEXT NOT NULL,nonce TEXT NOT NULL,created_at TEXT NOT NULL,expires_at TEXT NOT NULL,faculty_username TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS attendance(id INTEGER PRIMARY KEY AUTOINCREMENT,session_id INTEGER NOT NULL,student_id TEXT NOT NULL,timestamp TEXT NOT NULL,proof TEXT NOT NULL,previous_hash TEXT NOT NULL,record_hash TEXT NOT NULL,latitude REAL,longitude REAL,gps_accuracy REAL,photo_path TEXT,UNIQUE(session_id,student_id));""")
 # Backward-compatible migration for existing attendance.db files.
 for col, typ in [("latitude","REAL"),("longitude","REAL"),("gps_accuracy","REAL"),("photo_path","TEXT")]:
  try: c.execute(f"ALTER TABLE attendance ADD COLUMN {col} {typ}")
  except sqlite3.OperationalError: pass
 for n,u,p in [("Nikhil","Nikhil","nikhil143"),("Saketh","saketh","saketh123"),("Sai Charan","sai_charan","lizard143")]:
  c.execute("INSERT OR IGNORE INTO users(name,username,password_hash,role) VALUES(?,?,?,?)",(n,u,hp(p),"admin"))
 c.execute("INSERT OR IGNORE INTO users(name,username,password_hash,role) VALUES(?,?,?,?)",("Nithisha","Nithisha",hp("faculty@good"),"faculty"))
 for i in range(1,31):
  sid=f"23AIML{i:03d}"; c.execute("INSERT OR IGNORE INTO users(name,username,password_hash,role,faculty_username) VALUES(?,?,?,?,?)",(f"Student {i:02d}",sid,hp(f"Student@{i:03d}"),"student","Nithisha"))
 c.commit(); c.close()
def sig(sid,nonce,exp): return hmac.new(MASTER_SECRET,f"{sid}|{nonce}|{exp}".encode(),hashlib.sha256).hexdigest()
def rh(sid,student,ts,proof,prev,latitude=None,longitude=None):
 return hashlib.sha256(f"{sid}|{student}|{ts}|{proof}|{latitude}|{longitude}|{prev}".encode()).hexdigest()

@app.route("/")
def home():
 c=db(); stats={"proofs":c.execute("SELECT COUNT(*) n FROM attendance").fetchone()["n"],"students":c.execute("SELECT COUNT(*) n FROM users WHERE role='student'").fetchone()["n"],"faculty":c.execute("SELECT COUNT(*) n FROM users WHERE role='faculty'").fetchone()["n"],"sessions":c.execute("SELECT COUNT(*) n FROM sessions").fetchone()["n"]}; c.close()
 return render_template("home.html",stats=stats)

@app.route("/login",methods=["GET","POST"])
def login():
 if request.method=="POST":
  c=db(); u=c.execute("SELECT * FROM users WHERE username=? AND password_hash=?",(request.form["username"].strip(),hp(request.form["password"]))).fetchone(); c.close()
  if u: session.clear(); session.update(username=u["username"],name=u["name"],role=u["role"]); return redirect(url_for("dashboard"))
  flash("Invalid username or password.","danger")
 return render_template("login.html")
@app.route("/logout")
def logout(): session.clear(); return redirect(url_for("home"))

@app.route("/dashboard")
def dashboard():
 if "username" not in session:return redirect(url_for("login"))
 c=db(); role=session["role"]
 if role in ("admin","faculty"):
  if role=="faculty":
   students=c.execute("SELECT * FROM users WHERE role='student' AND faculty_username=? ORDER BY username",(session["username"],)).fetchall()
   rows=c.execute("SELECT a.*,s.course,s.room FROM attendance a JOIN sessions s ON s.id=a.session_id WHERE s.faculty_username=? ORDER BY a.id DESC LIMIT 50",(session["username"],)).fetchall()
  else:
   students=c.execute("SELECT * FROM users WHERE role='student' ORDER BY username").fetchall()
   rows=c.execute("SELECT a.*,s.course,s.room FROM attendance a JOIN sessions s ON s.id=a.session_id ORDER BY a.id DESC LIMIT 50").fetchall()
  total=len(rows); unique=len(set(r["student_id"] for r in rows))
  courses=c.execute("SELECT s.course,COUNT(*) n FROM attendance a JOIN sessions s ON s.id=a.session_id GROUP BY s.course").fetchall()
  c.close(); return render_template("staff_dashboard.html",role=role,students=students,rows=rows,courses=courses,total=total,unique=unique)
 student=c.execute("SELECT * FROM users WHERE username=?",(session["username"],)).fetchone()
 rows=c.execute("SELECT a.*,s.course,s.room FROM attendance a JOIN sessions s ON s.id=a.session_id WHERE a.student_id=? ORDER BY a.id DESC",(session["username"],)).fetchall()
 total=c.execute("SELECT COUNT(*) n FROM sessions").fetchone()["n"]; present=len(rows); c.close()
 return render_template("student_dashboard.html",student=student,rows=rows,total=total,present=present,pct=round(present/total*100,1) if total else 0)

@app.route("/create-session",methods=["POST"])
def create_session():
 if session.get("role") not in ("admin","faculty"):return "Unauthorized",403
 course=request.form["course"].strip(); room=request.form["room"].strip()
 try: minutes=max(1,min(int(request.form.get("minutes","5")),30))
 except: minutes=5
 now=datetime.now(timezone.utc); exp=now+timedelta(minutes=minutes); nonce=secrets.token_urlsafe(18)
 c=db(); cur=c.execute("INSERT INTO sessions(course,room,nonce,created_at,expires_at,faculty_username) VALUES(?,?,?,?,?,?)",(course,room,nonce,now.isoformat(),exp.isoformat(),session["username"])); sid=cur.lastrowid; c.commit(); c.close()
 return redirect(url_for("qr_page",session_id=sid))
def payload(s):
 q=urlencode({"nonce":s["nonce"],"exp":s["expires_at"],"sig":sig(s["id"],s["nonce"],s["expires_at"])})
 return f"{request.host_url}mark/{s['id']}?{q}"
@app.route("/session/<int:session_id>/qr")
def qr_page(session_id):
 c=db(); s=c.execute("SELECT * FROM sessions WHERE id=?",(session_id,)).fetchone(); c.close()
 if not s:return "Session not found",404
 return render_template("qr.html",s=s)
@app.route("/session/<int:session_id>/qr.png")
def qr_png(session_id):
 c=db(); s=c.execute("SELECT * FROM sessions WHERE id=?",(session_id,)).fetchone(); c.close()
 if not s:return "Session not found",404
 b=io.BytesIO(); qrcode.make(payload(s)).save(b,"PNG"); b.seek(0); return send_file(b,mimetype="image/png")

@app.route("/mark/<int:session_id>",methods=["GET","POST"])
def mark(session_id):
 c=db(); s=c.execute("SELECT * FROM sessions WHERE id=?",(session_id,)).fetchone(); c.close()
 if not s:return "Session not found",404
 nonce=request.args.get("nonce",""); exp=request.args.get("exp",""); received=request.args.get("sig","")
 try: expired=datetime.now(timezone.utc)>datetime.fromisoformat(exp)
 except: expired=True
 valid=hmac.compare_digest(received,sig(s["id"],nonce,exp)) and nonce==s["nonce"] and exp==s["expires_at"] and not expired
 if not valid:return render_template("error.html",message="Invalid or expired cryptographic attendance token."),403
 if request.method=="POST":
  student=request.form["student_id"].strip().upper()
  latitude=request.form.get("latitude","").strip()
  longitude=request.form.get("longitude","").strip()
  gps_accuracy=request.form.get("gps_accuracy","").strip()
  photo_data=request.form.get("photo_data","").strip()
  if not latitude or not longitude or not photo_data:
   return render_template("error.html",message="Camera photo and GPS location are required."),400
  try:
   lat=float(latitude); lon=float(longitude); accuracy=float(gps_accuracy or 0)
  except ValueError:
   return render_template("error.html",message="Invalid GPS coordinates."),400
  c=db(); u=c.execute("SELECT * FROM users WHERE username=? AND role='student'",(student,)).fetchone()
  if not u:c.close(); return render_template("error.html",message="Student account not found."),404
  if c.execute("SELECT id FROM attendance WHERE session_id=? AND student_id=?",(session_id,student)).fetchone():c.close();return render_template("error.html",message="Attendance already recorded."),409
  try:
   _, encoded=photo_data.split(",",1)
   image_bytes=base64.b64decode(encoded)
   filename=f"{student}_{session_id}_{uuid.uuid4().hex}.jpg"
   with open(os.path.join(PHOTO_FOLDER,filename),"wb") as f: f.write(image_bytes)
   photo_path=f"attendance_photos/{filename}"
  except Exception:
   c.close(); return render_template("error.html",message="Photo processing failed."),400
  ts=datetime.now(timezone.utc).isoformat(); proof=hmac.new(MASTER_SECRET,f"{s['id']}|{student}|{ts}|{nonce}".encode(),hashlib.sha256).hexdigest()
  last=c.execute("SELECT record_hash FROM attendance ORDER BY id DESC LIMIT 1").fetchone(); prev=last["record_hash"] if last else "GENESIS"; current=rh(s["id"],student,ts,proof,prev,lat,lon)
  c.execute("INSERT INTO attendance(session_id,student_id,timestamp,proof,previous_hash,record_hash,latitude,longitude,gps_accuracy,photo_path) VALUES(?,?,?,?,?,?,?,?,?,?)",(session_id,student,ts,proof,prev,current,lat,lon,accuracy,photo_path)); c.commit(); c.close()
  return render_template("success.html",student=u,s=s,hash=current)
 return render_template("mark.html",s=s)

@app.route("/attendance")
def attendance():
 if "username" not in session:return redirect(url_for("login"))
 c=db()
 if session["role"]=="student": rows=c.execute("SELECT a.*,s.course,s.room FROM attendance a JOIN sessions s ON s.id=a.session_id WHERE a.student_id=? ORDER BY a.id DESC",(session["username"],)).fetchall()
 elif session["role"]=="faculty": rows=c.execute("SELECT a.*,s.course,s.room FROM attendance a JOIN sessions s ON s.id=a.session_id WHERE s.faculty_username=? ORDER BY a.id DESC",(session["username"],)).fetchall()
 else: rows=c.execute("SELECT a.*,s.course,s.room FROM attendance a JOIN sessions s ON s.id=a.session_id ORDER BY a.id DESC").fetchall()
 c.close(); return render_template("attendance.html",rows=rows)

@app.route("/verify")
def verify():
 if "username" not in session:return redirect(url_for("login"))
 c=db(); rows=c.execute("SELECT a.*,s.course FROM attendance a JOIN sessions s ON s.id=a.session_id ORDER BY a.id").fetchall(); c.close()
 prev="GENESIS"; checked=[]; valid=True
 for r in rows:
  ok=r["previous_hash"]==prev and hmac.compare_digest(r["record_hash"],rh(r["session_id"],r["student_id"],r["timestamp"],r["proof"],r["previous_hash"],r["latitude"],r["longitude"]))
  checked.append((r,ok)); valid=valid and ok; prev=r["record_hash"]
 return render_template("verify.html",checked=checked,valid=valid)

init_db()
if __name__=="__main__": app.run(host="0.0.0.0",port=5000,debug=True)

