import sqlite3
from werkzeug.security import generate_password_hash

# Veritabanı bağlantısı
conn = sqlite3.connect("veritabani.db")

# users tablosunu oluştur (admin rolü eklendi!)
conn.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ad TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    parola TEXT NOT NULL,
    rol TEXT NOT NULL CHECK (rol IN ('kullanici', 'psikolog', 'admin')),
    uzmanlik TEXT
);
""")

# randevular tablosunu oluştur
conn.execute("""
CREATE TABLE IF NOT EXISTS randevular (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kullanici_id INTEGER NOT NULL,
    psikolog_id INTEGER NOT NULL,
    tarih TEXT NOT NULL,
    saat TEXT NOT NULL,
    aciklama TEXT,
    FOREIGN KEY (kullanici_id) REFERENCES users(id),
    FOREIGN KEY (psikolog_id) REFERENCES users(id)
);
""")

# Admin hesabı var mı kontrol et
admin = conn.execute("SELECT * FROM users WHERE rol = 'admin'").fetchone()

if not admin:
    hashed_password = generate_password_hash("admin123")
    conn.execute("""
        INSERT INTO users (ad, email, parola, rol, uzmanlik)
        VALUES (?, ?, ?, ?, ?)
    """, ("Admin", "admin@gmail.com", hashed_password, "admin", ""))
    print("✅ Admin hesabı oluşturuldu: admin@gmail.com / admin123")
else:
    print("ℹ️ Admin hesabı zaten var.")

# Veritabanı işlemlerini kaydet ve kapat
conn.commit()
conn.close()
print("✅ Veritabanı başarıyla oluşturuldu.")
