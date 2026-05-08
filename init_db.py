import sqlite3
import bcrypt
from cryptography.fernet import Fernet


# encryption key oluşturuyoruz
key = Fernet.generate_key()

with open("key.key", "wb") as file:
    file.write(key)


conn = sqlite3.connect("users.db")
cur = conn.cursor()


# users tablosu
cur.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password BLOB,
    role TEXT
)
""")


# notes tablosu
cur.execute("""
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    encrypted_note BLOB
)
""")


# admin hesabı oluşturuyoruz
admin_password = bcrypt.hashpw("admin123".encode(), bcrypt.gensalt())

try:
    cur.execute(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        ("admin", admin_password, "admin")
    )

except:
    pass


conn.commit()
conn.close()

print("Database created successfully")