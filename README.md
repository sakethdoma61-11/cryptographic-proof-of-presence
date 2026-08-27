# Cryptographic Proof of Presence

A secure QR-based attendance management system with cryptographic
verification, attendance analytics, and faculty study-material sharing.

## Features

- Secure Admin, Faculty and Student login
- QR-based attendance
- HMAC-SHA256 attendance verification
- Cryptographic hash chaining
- Attendance analytics
- Faculty dashboard
- Student dashboard
- Faculty study-material upload
- Student material download
- SHA-256 file integrity verification
- Tamper detection
- Attendance history

## Technology Stack

- Python
- Flask
- SQLite
- HTML
- CSS
- JavaScript
- SHA-256
- HMAC-SHA256
- QR Code

## Project Structure

```text
cryptographic-proof-of-presence/
│
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
│
├── templates/
│   ├── base.html
│   ├── login.html
│   ├── dashboard.html
│   ├── student_dashboard.html
│   ├── materials.html
│   └── material_verify.html
│
├── static/
│   └── style.css
│
└── uploads/