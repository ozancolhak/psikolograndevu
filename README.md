# Psikolog Randevu Sistemi 🧠

Bu proje, danışanların psikologlardan kolayca randevu alabilmesini sağlayan basit ama güvenli bir web uygulamasıdır.

## 🚀 Kullanılan Teknolojiler

- Python
- Flask
- SQLite
- Jinja2 (HTML Template Engine)
- Bootstrap 5
- CSS
- Dateutil

## 🔐 Güvenlik Özellikleri

- Parola hashing (Werkzeug ile)
- Rol bazlı erişim kontrolü (admin, psikolog, kullanıcı)
- Oturum yönetimi ve koruma
- SQL Injection'a karşı önlem (parametreli sorgular)
- Zaman kontrolü (geçmişe randevu engeli)
- Kullanıcı doğrulama sistemi

## 🛠 Kurulum

1. Gerekli paketleri yükleyin:

-bash
pip install -r requirements.txt

-bash
python init_db.py
#Veritabanını başlatın:

-bash
python app.py
#Uygulamayı başlatın:
