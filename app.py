import sqlite3
import bcrypt
from cryptography.fernet import Fernet
from flask import Flask, render_template, request, redirect, session

app = Flask(__name__)
app.secret_key = "secret123"


# burada encryption key oluşturuyorum
# secret data encrypt ve decrypt işlemleri için kullanacağım
key = Fernet.generate_key()
cipher = Fernet(key)


@app.route("/")
def home():
    return redirect("/login")


# login işlemi
# kullanıcı adı ve şifre kontrolü yapıyorum
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        user = request.form["username"]
        pw = request.form["password"]

        conn = sqlite3.connect("users.db")
        cur = conn.cursor()

        cur.execute(
            "SELECT * FROM users WHERE username = ?",
            (user,)
        )

        data = cur.fetchone()

        conn.close()

        if data:

            dbPw = data[2]

            # burada hashlenmiş şifre kontrolü yapıyorum
            if bcrypt.checkpw(pw.encode(), dbPw):

                session["user"] = data[1]
                session["role"] = data[3]

                return redirect("/dashboard")

        return "wrong username or password"

    return render_template("login.html")


# register işlemi
# şifreyi hashleyip kaydediyorum
# ayrıca secret bilgiyi encrypt edip databasee atıyorum
@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        user = request.form["username"]
        pw = request.form["password"]
        text = request.form["secret_data"]

        hashedPw = bcrypt.hashpw(
            pw.encode(),
            bcrypt.gensalt()
        )

        encText = cipher.encrypt(text.encode())

        conn = sqlite3.connect("users.db")
        cur = conn.cursor()

        # ilk kullanıcı admin olsun diye bunu yaptım
        cur.execute("SELECT COUNT(*) FROM users")

        total = cur.fetchone()[0]

        role = "user"

        if total == 0:
            role = "admin"

        cur.execute(
            "INSERT INTO users(username,password,role,secretText) VALUES(?,?,?,?)",
            (user, hashedPw, role, encText)
        )

        conn.commit()
        conn.close()

        return redirect("/login")

    return render_template("register.html")


# kullanıcı giriş yaptıysa panel açılıyor
# encrypted veri burada decrypt edilip gösteriliyor
@app.route("/dashboard")
def dashboard():

    if "user" not in session:
        return redirect("/login")

    conn = sqlite3.connect("users.db")
    cur = conn.cursor()

    cur.execute(
        "SELECT secretText FROM users WHERE username = ?",
        (session["user"],)
    )

    encData = cur.fetchone()[0]

    conn.close()

    normalText = cipher.decrypt(encData).decode()

    return render_template(
        "dashboard.html",
        username=session["user"],
        role=session["role"],
        secret_data=normalText
    )


# sadece admin girsin diye kontrol yaptım
# normal user girerse engellenecek
@app.route("/admin")
def adminPage():

    if "user" not in session:
        return redirect("/login")

    if session["role"] != "admin":
        return "Bu sayfaya sadece admin girebilir"

    return render_template("admin.html")


# çıkış yapınca session temizleniyor
@app.route("/logout")
def logout():

    session.clear()

    return redirect("/login")


if __name__ == "__main__":
    app.run(debug=True)