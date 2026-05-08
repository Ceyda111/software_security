import sqlite3
import bcrypt
from cryptography.fernet import Fernet
from flask import Flask, render_template, request, redirect, session

app = Flask(__name__)

# session işlemleri için secret key
app.secret_key = "change_this_secret_key"


# burada daha önce oluşturduğumuz encryption key dosyasını okuyorum
with open("key.key", "rb") as file:
    key = file.read()

# encrypt ve decrypt işlemleri için kullanacağım
cipher = Fernet(key)


# database bağlantısı için küçük bir fonksiyon yazdım
def get_db():
    conn = sqlite3.connect("users.db")
    return conn


# ana sayfa açılırsa direkt login sayfasına yönlendiriyorum
@app.route("/")
def home():
    return redirect("/login")


# kullanıcı kayıt işlemi
@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        # yeni kayıt olan herkes normal user oluyor
        role = "user"

        # şifreyi direkt kaydetmiyorum
        # bcrypt ile hashliyorum
        hashed_password = bcrypt.hashpw(
            password.encode(),
            bcrypt.gensalt()
        )

        conn = get_db()
        cur = conn.cursor()

        try:
            # parameterized query kullandım
            # sql injection riskini azaltmak için
            cur.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (username, hashed_password, role)
            )

            conn.commit()
            conn.close()

            return redirect("/login")

        except:
            conn.close()

            # aynı username varsa hata verecek
            return "Username already exists"

    return render_template("register.html")


# login işlemi
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()
        cur = conn.cursor()

        # kullanıcıyı database içinde arıyorum
        cur.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        )

        user = cur.fetchone()

        conn.close()

        # kullanıcı varsa şifre kontrolü yapıyorum
        if user:

            stored_password = user[2]

            # hashlenmiş şifreyi kontrol ediyor
            if bcrypt.checkpw(password.encode(), stored_password):

                # session içine kullanıcı bilgilerini kaydediyorum
                session["user_id"] = user[0]
                session["username"] = user[1]
                session["role"] = user[3]

                return redirect("/dashboard")

        return "Wrong username or password"

    return render_template("login.html")


# kullanıcı paneli
@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():

    # kullanıcı giriş yapmadıysa login'e atıyorum
    if "user_id" not in session:
        return redirect("/login")

    # kullanıcı yeni not eklerse
    if request.method == "POST":

        note = request.form["note"]

        # notu database'e kaydetmeden önce encrypt ediyorum
        encrypted_note = cipher.encrypt(note.encode())

        conn = get_db()
        cur = conn.cursor()

        cur.execute(
            "INSERT INTO notes (user_id, encrypted_note) VALUES (?, ?)",
            (session["user_id"], encrypted_note)
        )

        conn.commit()
        conn.close()

        return redirect("/dashboard")

    conn = get_db()
    cur = conn.cursor()

    # kullanıcının kendi notlarını çekiyorum
    cur.execute(
        "SELECT encrypted_note FROM notes WHERE user_id = ?",
        (session["user_id"],)
    )

    notes = cur.fetchall()

    conn.close()

    decrypted_notes = []

    # database'den gelen encrypted notları çözüyorum
    for note in notes:

        decrypted_note = cipher.decrypt(note[0]).decode()

        decrypted_notes.append(decrypted_note)

    return render_template(
        "dashboard.html",
        username=session["username"],
        role=session["role"],
        notes=decrypted_notes
    )


# admin paneli
@app.route("/admin")
def admin():

    # giriş yapılmadıysa login sayfasına gönderiyorum
    if "user_id" not in session:
        return redirect("/login")

    # admin değilse admin sayfasına giremesin
    if session["role"] != "admin":
        return "Access denied. Admins only."

    conn = get_db()
    cur = conn.cursor()

    # tüm kullanıcıları çekiyorum
    cur.execute("SELECT id, username, role FROM users")

    users = cur.fetchall()

    conn.close()

    return render_template("admin.html", users=users)


# çıkış işlemi
@app.route("/logout")
def logout():

    # session temizleniyor
    session.clear()

    return redirect("/login")


if __name__ == "__main__":
    app.run(debug=True)