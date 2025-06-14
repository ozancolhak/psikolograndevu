from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, session, flash
from dateutil import parser
from datetime import datetime
import sqlite3

app = Flask(__name__)
app.secret_key = "supersecretkey"

# CSRF koruması
csrf = CSRFProtect(app)

# Güvenli çerez ayarları
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,  # HTTPS kullanıyorsan True
    SESSION_COOKIE_SAMESITE="Lax"
)

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[]
)

# Güvenlik headerları
@app.after_request
def set_security_headers(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'  # Clickjacking koruması
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'  # HSTS
    response.headers['X-Content-Type-Options'] = 'nosniff'  # MIME tipi koruması
    # İstersen CSP ekleyebilirsin
    # response.headers['Content-Security-Policy'] = "default-src 'self';"
    return response


def get_db_connection():
    conn = sqlite3.connect("veritabani.db")
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/")
def index():
    conn = get_db_connection()
    psikologlar = conn.execute("SELECT * FROM users WHERE rol = 'psikolog'").fetchall()
    conn.close()
    return render_template("index.html", psikologlar=psikologlar)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        ad = request.form["ad"]
        email = request.form["email"]
        parola = generate_password_hash(request.form["parola"])
        rol = request.form["rol"]
        uzmanlik = request.form.get("uzmanlik") if rol == "psikolog" else None

        conn = get_db_connection()
        existing = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if existing:
            flash("Bu email zaten kayıtlı.", "error")
        else:
            conn.execute("INSERT INTO users (ad, email, parola, rol, uzmanlik) VALUES (?, ?, ?, ?, ?)",
                         (ad, email, parola, rol, uzmanlik))
            conn.commit()
            flash("Kayıt başarılı, lütfen giriş yapın.", "success")
        conn.close()
        return redirect(url_for("login"))

    csrf_token = generate_csrf()
    return render_template("register.html", csrf_token=csrf_token)


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("3 per minute")
def login():
    if request.method == "POST":
        email = request.form["email"]
        parola = request.form["parola"]

        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        conn.close()

        if user and check_password_hash(user["parola"], parola):
            session["user_id"] = user["id"]
            session["user_ad"] = user["ad"]
            session["rol"] = user["rol"]

            if user["rol"] == "kullanici":
                return redirect(url_for("index"))
            elif user["rol"] == "psikolog":
                return redirect(url_for("psikolog_panel"))
            elif user["rol"] == "admin":
                return redirect(url_for("admin_panel"))
        else:
            flash("Email veya parola hatalı.", "error")

    csrf_token = generate_csrf()
    return render_template("login.html", csrf_token=csrf_token)



@app.route("/logout")
def logout():
    session.clear()
    flash("Başarıyla çıkış yapıldı.", "success")
    return redirect(url_for("login"))

def get_saat_durumlari(psikolog_id, tarih):
    saatler = [f"{h:02d}" for h in range(10, 21)]

    conn = get_db_connection()
    randevular = conn.execute(
        "SELECT saat FROM randevular WHERE psikolog_id = ? AND tarih = ?",
        (psikolog_id, tarih)
    ).fetchall()
    conn.close()

    dolu_saatler = {r["saat"] for r in randevular}

    saatler_durum = []
    for saat in saatler:
        durum = "mesgul" if saat in dolu_saatler else "bos"
        saatler_durum.append({"saat": saat, "durum": durum})
    return saatler_durum

@app.route("/randevu_al/<int:psikolog_id>", methods=["GET", "POST"])
def randevu_al(psikolog_id):
    if "user_id" not in session or session.get("rol") != "kullanici":
        flash("Randevu alabilmek için giriş yapmanız ve kullanıcı olmanız gerekir.", "error")
        return redirect(url_for("login"))

    current_date = datetime.now().strftime("%Y-%m-%d")
    saatler = get_saat_durumlari(psikolog_id, current_date)

    if request.method == "POST":
        tarih = request.form["tarih"]
        saat = request.form["saat"]
        try:
            secilen = parser.parse(f"{tarih} {saat}")
            if secilen < datetime.now():
                raise ValueError("Geçmiş tarih")
            if saat not in [s['saat'] for s in get_saat_durumlari(psikolog_id, tarih) if s['durum'] == 'bos']:
                raise ValueError("Seçilen saat meşgul")
        except Exception:
            flash("Geçersiz tarih veya saat.", "error")
            saatler = get_saat_durumlari(psikolog_id, tarih)
            saatler_durum = {s['saat']: s['durum'] for s in saatler}
            return render_template("randevu_al.html", current_date=current_date, saatler_durum=saatler_durum, selected_date=tarih)

        conn = get_db_connection()
        conn.execute(
            "INSERT INTO randevular (kullanici_id, psikolog_id, tarih, saat, aciklama) VALUES (?, ?, ?, ?, '')",
            (session["user_id"], psikolog_id, tarih, saat)
        )
        conn.commit()
        conn.close()

        flash("Randevu başarıyla alındı.", "success")
        return redirect(url_for("randevularim"))

    saatler_durum = {s['saat']: s['durum'] for s in saatler}
    return render_template("randevu_al.html", current_date=current_date, saatler_durum=saatler_durum, selected_date=current_date)


@app.route("/randevularim")
def randevularim():
    if "user_id" not in session or session.get("rol") != "kullanici":
        flash("Lütfen giriş yapınız.", "error")
        return redirect(url_for("login"))

    conn = get_db_connection()
    randevular = conn.execute("""
        SELECT r.id, r.tarih, r.saat, r.aciklama, u.ad AS psikolog_ad
        FROM randevular r
        JOIN users u ON r.psikolog_id = u.id
        WHERE r.kullanici_id = ?
        ORDER BY r.tarih, r.saat
    """, (session["user_id"],)).fetchall()
    conn.close()

    return render_template("randevularim.html", randevular=randevular)

@app.route("/psikolog_panel")
def psikolog_panel():
    if "user_id" not in session or session.get("rol") != "psikolog":
        flash("Psikolog olarak giriş yapınız.", "error")
        return redirect(url_for("login"))

    conn = get_db_connection()
    randevular = conn.execute("""
        SELECT r.id, r.tarih, r.saat, r.aciklama, u.ad AS danisan_ad
        FROM randevular r
        JOIN users u ON r.kullanici_id = u.id
        WHERE r.psikolog_id = ?
        ORDER BY r.tarih, r.saat
    """, (session["user_id"],)).fetchall()
    conn.close()

    return render_template("psikolog_panel.html", randevular=randevular)

@app.route("/randevu_sil/<int:randevu_id>", methods=["POST"])
def randevu_sil(randevu_id):
    if "user_id" not in session:
        flash("Giriş yapınız.", "error")
        return redirect(url_for("login"))

    conn = get_db_connection()
    if session["rol"] == "kullanici":
        conn.execute("DELETE FROM randevular WHERE id = ? AND kullanici_id = ?", (randevu_id, session["user_id"]))
    elif session["rol"] == "psikolog":
        conn.execute("DELETE FROM randevular WHERE id = ? AND psikolog_id = ?", (randevu_id, session["user_id"]))
    conn.commit()
    conn.close()

    flash("Randevu silindi.", "success")
    return redirect(url_for("randevularim" if session["rol"] == "kullanici" else "psikolog_panel"))

@app.route("/admin_panel", methods=["GET", "POST"])
def admin_panel():
    if "user_id" not in session or session.get("rol") != "admin":
        flash("Admin olarak giriş yapmalısınız.", "error")
        return redirect(url_for("login"))

    conn = get_db_connection()

    if request.method == "POST":
        ad = request.form["ad"]
        email = request.form["email"]
        parola = generate_password_hash(request.form["parola"])
        uzmanlik = request.form["uzmanlik"]

        existing = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if existing:
            flash("Bu email zaten kayıtlı.", "error")
        else:
            conn.execute(
                "INSERT INTO users (ad, email, parola, rol, uzmanlik) VALUES (?, ?, ?, 'psikolog', ?)",
                (ad, email, parola, uzmanlik)
            )
            conn.commit()
            flash("Psikolog başarıyla eklendi.", "success")
            conn.close()
            return redirect(url_for("admin_panel"))

    psikologlar = conn.execute("SELECT * FROM users WHERE rol = 'psikolog'").fetchall()
    danisanlar = conn.execute("SELECT * FROM users WHERE rol = 'kullanici'").fetchall()
    conn.close()
    return render_template("admin_panel.html", psikologlar=psikologlar, danisanlar=danisanlar)

@app.route("/psikolog_sil/<int:id>", methods=["POST"])
def psikolog_sil(id):
    if "user_id" not in session or session.get("rol") != "admin":
        flash("Admin olarak giriş yapmalısınız.", "error")
        return redirect(url_for("login"))

    conn = get_db_connection()
    conn.execute("DELETE FROM users WHERE id = ? AND rol = 'psikolog'", (id,))
    conn.commit()
    conn.close()

    flash("Psikolog silindi.", "success")
    return redirect(url_for("admin_panel"))

if __name__ == "__main__":
    app.run(debug=True)
