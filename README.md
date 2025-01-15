# VIP Casino Bot Kurulum Rehberi

## Gereksinimler
- Python 3.9 veya üzeri
- pip (Python paket yöneticisi)

## Kurulum Adımları

1. Projeyi bilgisayarınıza indirin

2. Gerekli paketleri yükleyin:
```bash
pip install -r requirements.txt
```

3. `.env` dosyasını oluşturun ve aşağıdaki bilgileri ekleyin:
```
BOT_TOKEN=your_bot_token_here
BOT_USERNAME=your_bot_username_here
GROUP_ID=your_group_id_here
LOG_CHANNEL_ID=your_log_channel_id_here
ADMIN_USERNAME=admin_username_here
ADMIN_PASSWORD=admin_password_here
FLASK_DEBUG=True
FLASK_HOST=0.0.0.0
FLASK_PORT=5000
DATABASE_URI=sqlite:///database.db
```

4. Uygulamayı başlatın:
```bash
python main.py
```

5. Tarayıcıdan http://127.0.0.1:5000 adresine gidin

## Admin Paneli
- Varsayılan admin kullanıcı adı: becool
- Varsayılan admin şifresi: muharrem

## Özellikler
- Kullanıcı kaydı ve onaylama sistemi
- Telegram bot entegrasyonu
- Hediye kodu sistemi
- Admin paneli
- Detaylı log sistemi

## Klasör Yapısı
```
├── main.py           # Ana uygulama dosyası
├── app.py           # Flask uygulaması
├── bot.py           # Telegram bot kodları
├── config.py        # Konfigürasyon ayarları
├── models.py        # Veritabanı modelleri
├── extensions.py    # Flask eklentileri
├── messages.py      # Mesaj şablonları
├── requirements.txt # Gerekli paketler
├── instance/        # Veritabanı ve geçici dosyalar
├── logs/           # Log dosyaları
└── templates/      # HTML şablonları
``` 