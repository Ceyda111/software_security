import os
import sqlite3
import bcrypt
from contextlib import contextmanager
from dotenv import load_dotenv
from cryptography.fernet import Fernet
from flask import Flask, render_template, request, redirect, session
from datetime import datetime

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "fallback-secret-key-for-dev")

# Security flags for session cookies
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False, # Set to True if deploying with HTTPS
    SESSION_COOKIE_SAMESITE='Lax',
)

# Load the encryption key for Application-Level Encryption
with open("key.key", "rb") as file:
    key = file.read()
cipher = Fernet(key)

@contextmanager
def get_db():
    conn = sqlite3.connect("users.db")
    try:
        yield conn
    finally:
        conn.close()

def log_event(action, user_id=None, username=None):
    """Encrypts the action and logs the event."""
    ip_addr = request.remote_addr
    encrypted_action = cipher.encrypt(action.encode())

    local_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO audit_logs (user_id, username, action, ip_address, timestamp) VALUES (?, ?, ?, ?, ?)",
            (user_id, username, encrypted_action, ip_addr, local_time)
        )
        conn.commit()

@app.route("/")
def home():
    return redirect("/login")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if len(password) < 8:
            return "Password must be at least 8 characters long."

        role = "user"
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

        with get_db() as conn:
            cur = conn.cursor()
            try:
                cur.execute(
                    "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                    (username, hashed_password, role)
                )
                conn.commit()
                log_event("USER_REGISTERED", username=username)
                return redirect("/login")
            except:
                return "Username already exists"

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = cur.fetchone()

        if user and bcrypt.checkpw(password.encode(), user[2]):
            session["user_id"] = user[0]
            session["username"] = user[1]
            session["role"] = user[3]
            
            log_event("LOGIN_SUCCESS", user_id=user[0], username=user[1])
            return redirect("/dashboard")
        
        log_event("LOGIN_FAILED", username=username)
        return "Wrong username or password"

    return render_template("login.html")

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "user_id" not in session:
        return redirect("/login")

    if request.method == "POST":
        note = request.form["note"]
        encrypted_note = cipher.encrypt(note.encode())

        with get_db() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO notes (user_id, encrypted_note) VALUES (?, ?)",
                (session["user_id"], encrypted_note)
            )
            conn.commit()
        
        log_event("NOTE_CREATED", user_id=session["user_id"], username=session["username"])
        return redirect("/dashboard")

    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT encrypted_note FROM notes WHERE user_id = ?", (session["user_id"],))
        notes = cur.fetchall()

    decrypted_notes = []
    for note in notes:
        decrypted_note = cipher.decrypt(note[0]).decode()
        decrypted_notes.append(decrypted_note)

    return render_template(
        "dashboard.html", 
        username=session["username"], 
        role=session["role"], 
        notes=decrypted_notes
    )

@app.route("/admin")
def admin():
    if "user_id" not in session:
        return redirect("/login")

    if session["role"] != "admin":
        log_event("UNAUTHORIZED_ADMIN_ATTEMPT", user_id=session["user_id"], username=session["username"])
        return "Access denied. Admins only.", 403

    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, username, role FROM users")
        users = cur.fetchall()
        
        cur.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 50")
        raw_logs = cur.fetchall()

    # Decrypt the actions in the audit logs before sending to the template
    decrypted_logs = []
    for log in raw_logs:
        try:
            # log[3] is the encrypted action BLOB
            decrypted_action = cipher.decrypt(log[3]).decode()
        except:
            decrypted_action = "Decryption Failed"
        
        # Rebuild the log tuple with the decrypted action: (id, user_id, username, action, ip, timestamp)
        decrypted_logs.append((log[0], log[1], log[2], decrypted_action, log[4], log[5]))

    return render_template("admin.html", users=users, logs=decrypted_logs)

@app.route("/logout")
def logout():
    if "user_id" in session:
        log_event("LOGOUT", user_id=session["user_id"], username=session["username"])
    session.clear()
    return redirect("/login")

if __name__ == "__main__":
    app.run(debug=False)