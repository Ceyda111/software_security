import sqlite3
import bcrypt
import os
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()

# Key Management: Ensure key.key exists for Fernet
if not os.path.exists("key.key"):
    key = Fernet.generate_key()
    with open("key.key", "wb") as file:
        file.write(key)
    print("New encryption key generated.")
else:
    print("Existing key.key found. Keeping current encryption key.")

def init_db():
    # Use standard sqlite3 (No C-compilers needed)
    conn = sqlite3.connect("users.db")
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password BLOB,
        role TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        encrypted_note BLOB,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        action BLOB, 
        ip_address TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Initial Admin Setup
    hashed_admin_pass = bcrypt.hashpw("admin123".encode(), bcrypt.gensalt())
    try:
        cur.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                    ("admin", hashed_admin_pass, "admin"))
        print("Admin user created.")
    except sqlite3.IntegrityError:
        print("Admin user already exists.")

    conn.commit()
    conn.close()
    print("Database initialized successfully.")

if __name__ == "__main__":
    init_db()