
import sqlite3
import bcrypt
from flask import Flask, render_template, request, redirect, session

app = Flask(__name__)
app.secret_key = "change_this_to_a_secret"

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = request.form["username"]
        pw = request.form["password"]

        conn = sqlite3.connect("users.db")
        cur = conn.cursor()

        cur.execute("SELECT * FROM users WHERE username = ?", (user,))
        data = cur.fetchone()
        conn.close()

        if data:
            dbPw = data[2]
            if bcrypt.checkpw(pw.encode(), dbPw):
                session["user"] = data[1]
                session["role"] = data[3]
                return redirect("/dashboard")

        return "wrong username or password"

    return render_template("login.html")


# kullanıcı giriş yaptıysa dashboard açılıyor
# burada encrypted veri decrypt edilip gösteriliyor
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


# sadece admin rolü girsin diye kontrol yaptım
# user hesabı girerse access denied dönecek
@app.route("/admin")
def adminPage():

    if "user" not in session:
        return redirect("/login")

    if session["role"] != "admin":
        return "Access Denied"

    return render_template("admin.html")


# çıkış yapınca session temizleniyor
@app.route("/logout")
def logout():

    session.clear()

    return redirect("/login")


if __name__ == "__main__":
    app.run(debug=True)