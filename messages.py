class Messages:
    # Giriş/Kayıt Mesajları
    LOGIN_SUCCESS = """
🌟 Giriş Başarılı! Hoş Geldiniz!

👋 Sevgili {username},
✨ Sizi tekrar aramızda görmek harika!

📌 Son Giriş Bilgileri:
• 📅 Tarih: {date}
• 🌍 IP: {ip}
• 📱 Cihaz: {device}

🎮 Size Özel Fırsatlar:
• 🎁 Günlük hediye kodları
• 👑 VIP avantajları
• 🎯 Özel etkinlikler

📢 Duyurularımızı takip etmeyi unutmayın!
"""

    REGISTER_SUCCESS = """
🎉 Kayıt İşleminiz Başarılı!

✨ Aramıza Hoş Geldiniz {username}!

📝 Hesap Bilgileriniz:
• 👤 Kullanıcı Adı: {username}
• 📧 Email: {email}
• 🔑 Özel Kod: {special_code}

⚠️ Önemli Hatırlatmalar:
• 📱 Telegram hesabınızı bağlamayı unutmayın
• 🔒 Güvenlik için şifrenizi kimseyle paylaşmayın
• ⚡ Her hesap için tek Telegram bağlantısı yapılabilir

📌 Sonraki Adımlar:
1️⃣ Yönetici onayını bekleyin
2️⃣ Telegram botunu başlatın
3️⃣ Hesabınızı bağlayın

🎮 Hazır olduğunuzda size özel kodlar sizi bekliyor!
"""

    # Telegram Bot Mesajları
    BOT_WELCOME = """
🎰 Hoş Geldiniz! VIP Casino Dünyasına Adım Atın! 🎰

👋 Sevgili {first_name},
🌟 Özel VIP dünyamıza hoş geldiniz! Size muhteşem fırsatlar sunmaktan mutluluk duyuyoruz.

💎 Premium Avantajlarınız:
• 🎁 Günlük özel hediye kodları
• 💰 Yüksek kazanç oranları
• 🎯 Özel VIP etkinlikler
• 👑 VIP üyelere özel bonuslar
• 🔔 Anlık kazanç bildirimleri
• 🛡️ 7/24 öncelikli destek

🚀 Başlamak İçin Adımlar:
1️⃣ Web sitemizden ücretsiz kayıt olun
2️⃣ /link komutunu kullanarak özel kodunuzu alın
3️⃣ Kodunuzu web sitesinde aktifleştirin
4️⃣ VIP ayrıcalıklarınızı kullanmaya başlayın!

⚠️ Önemli Kurallar:
• 🔒 Her kullanıcı tek hesap açabilir
• ⚡ Hesap bağlama kalıcıdır
• 🎯 Dürüst oyun politikası
• 🚫 Hile = Kalıcı ban

📌 Yararlı Komutlar:
• /help - Tüm komutları gör
• /profile - Profilini görüntüle
• /vip - VIP durumunu kontrol et
• /bonus - Günlük bonuslarını al
• /stats - İstatistiklerini gör

🎮 Özel Etkinlikler:
• 🎲 Günlük çekilişler
• 🎯 Turnuvalar
• 🎁 Sürpriz ödüller
• 💎 VIP özel oyunlar

💫 Başarılar ve bol şanslar dileriz!
✨ VIP ekibiniz her zaman yanınızda!

🔥 Hemen başlamak için /link yazın!
"""

    ACCOUNT_LINK_SUCCESS = """
✅ Telegram Hesabı Başarıyla Bağlandı!

🎯 Bağlantı Detayları:
• 👤 Kullanıcı: {username}
• 📱 Telegram: @{telegram_username}
• 📅 Tarih: {date}

🎮 Artık Tüm Özellikleri Kullanabilirsiniz:
• 🎁 Özel kodları kullanma
• 👑 VIP fırsatlarından yararlanma
• 🔔 Anlık bildirimler alma
• 📊 İstatistikleri görüntüleme

📌 Önemli Komutlar:
• /help - Tüm komutları görüntüle
• /profile - Profilini görüntüle
• /codes - Aktif kodları listele

✨ İyi eğlenceler!
"""

    # Kod Kullanım Mesajları
    CODE_USED_SUCCESS = """
🎉 Kod Başarıyla Kullanıldı!

📌 Kod Detayları:
• 🎁 Kod: {code}
• 📅 Kullanım: {date}
• 🏆 Kategori: {category}

⏳ Bir sonraki kod kullanımı için kalan süre: {next_use_time}

✨ Keyifli kullanımlar dileriz!
"""

    CODE_ERROR = """
❌ Kod Kullanılamadı!

⚠️ Hata Nedeni:
• {error_reason}

📌 Kontrol Edilecekler:
• 🕒 Kod süresi dolmuş olabilir
• 👥 Kullanım limiti dolmuş olabilir
• ⚡ 24 saat kuralı geçerli olabilir

🔄 Lütfen tekrar deneyin veya yönetici ile iletişime geçin
"""

    # Admin Panel Mesajları
    ADMIN_USER_APPROVED = """
✅ Kullanıcı Onaylandı!

👤 Kullanıcı Bilgileri:
• 📝 Ad: {username}
• 📧 Email: {email}
• 🌍 IP: {ip}
• 📱 Telegram: {telegram}

📅 İşlem Detayları:
• ⏰ Tarih: {date}
• 👨‍💼 Onaylayan: {admin}

🔔 Kullanıcıya bilgilendirme mesajı gönderildi
"""

    ADMIN_USER_REJECTED = """
❌ Kullanıcı Reddedildi

👤 Kullanıcı Bilgileri:
• 📝 Ad: {username}
• 📧 Email: {email}
• 🌍 IP: {ip}

📅 İşlem Detayları:
• ⏰ Tarih: {date}
• 👨‍💼 Reddeden: {admin}
• ❓ Sebep: {reason}

🔔 Kullanıcıya red mesajı iletildi
"""

    # VIP Mesajları
    VIP_ACTIVATED = """
👑 VIP Üyelik Aktifleştirildi!

🌟 Tebrikler {username}!

📅 VIP Detayları:
• ⏰ Başlangıç: {start_date}
• 🔚 Bitiş: {end_date}
• 🏆 Seviye: {level}

✨ VIP Ayrıcalıklarınız:
• 💎 Premium kodlar
• 🎁 Günlük hediyeler
• ⚡ Hızlı destek
• 🎯 Özel etkinlikler

📌 VIP komutları için /vip yazabilirsiniz

🎮 VIP ayrıcalıklarının keyfini çıkarın!
"""

    # Güvenlik Mesajları
    SECURITY_ALERT = """
🚨 Güvenlik Uyarısı!

⚠️ Tespit Edilen Durum:
• {alert_type}
• 📅 Tarih: {date}
• 🌍 IP: {ip}

📌 Alınan Önlemler:
• 🔒 Hesap güvenliği artırıldı
• 📝 Log kaydı oluşturuldu
• ⚡ İlgili IP engellendi

🛡️ Öneriler:
• 🔑 Şifrenizi değiştirin
• 📱 2FA kullanın
• 🔍 Hesap aktivitelerini kontrol edin

❗ Siz değilseniz hemen yönetici ile iletişime geçin
"""

    # Bakım/Hata Mesajları
    MAINTENANCE = """
🛠️ Planlı Bakım Bildirimi

⚙️ Bakım Detayları:
• 📅 Tarih: {date}
• ⏱️ Süre: {duration}
• 📝 Açıklama: {description}

📌 Önemli Bilgiler:
• 🔧 Sistemsel iyileştirmeler yapılacak
• ⚡ Hizmet geçici olarak duracak
• 🔄 İşlemlerinizi daha sonra yapın

⏳ Tahmini bitiş: {end_time}

📢 Anlayışınız için teşekkürler!
"""

    ERROR_500 = """
⚠️ Sistem Hatası!

❌ Hata Detayları:
• 🔍 Kod: 500
• ⏰ Zaman: {time}
• 📝 Tip: {error_type}

📌 Yapılacaklar:
1️⃣ Sayfayı yenileyin
2️⃣ Cache temizleyin
3️⃣ Tekrar deneyin

🔧 Teknik ekibimiz sorunu çözüyor
📞 Sorun devam ederse yönetici ile iletişime geçin

🙏 Anlayışınız için teşekkürler!
"""

    # Bildirim Mesajları
    NEW_CODE_NOTIFICATION = """
🎁 Yeni Kod Yayınlandı!

📢 Acele Edin! Sınırlı Sayıda!

🎯 Kod Detayları:
• 🏷️ Kategori: {category}
• ⏰ Süre: {duration}
• 👥 Kalan: {remaining}

⚡ Hemen Kullanmak İçin:
1️⃣ Siteye giriş yapın
2️⃣ Kod bölümüne gidin
3️⃣ Kodu aktif edin

🏃‍♂️ Acele edin, stoklar tükenmeden yerinizi alın!
"""

    DAILY_REMINDER = """
🌅 Günaydın {username}!

📅 Günlük Hatırlatmalar:
• 🎁 Yeni kodlar eklendi
• 👑 VIP fırsatları aktif
• 🎯 Özel etkinlikler başladı

📊 Hesap Durumu:
• 🏆 Seviye: {level}
• ⭐ VIP: {vip_status}
• 📈 Toplam: {total_codes}

🎮 Hemen giriş yapın ve fırsatları kaçırmayın!
"""

    # Log Mesajları
    LOG_USERNAME_CHANGE = """
📝 Kullanıcı Adı Değişikliği

👤 Kullanıcı Bilgileri:
• 📎 ID: {user_id}
• 📧 Email: {email}
• 📱 Telegram: @{telegram_username}

🔄 Değişiklik:
• ❌ Eski: {old_username}
• ✅ Yeni: {new_username}
• ⏰ Tarih: {date}
• 🌍 IP: {ip}

📊 Hesap Durumu:
• ✨ VIP: {is_vip}
• 📅 Kayıt: {register_date}
• 🔰 Seviye: {level}
"""

    LOG_BLACKLIST_ADD = """
⛔ Kara Liste - Yeni Ekleme

👤 Kullanıcı Bilgileri:
• 📎 ID: {user_id}
• 👤 Kullanıcı: {username}
• 📱 Telegram: @{telegram_username}
• 📧 Email: {email}

⚠️ Kara Liste Detayları:
• 📝 Sebep: {reason}
• 👮 Ekleyen: {admin}
• ⏰ Tarih: {date}
• 🌍 IP: {ip}

🚫 Uygulanan Kısıtlamalar:
• ❌ Kod kullanımı engellendi
• ❌ Grup erişimi engellendi
• ❌ Bot komutları engellendi
"""

    LOG_BLACKLIST_REMOVE = """
✅ Kara Liste - Üye Çıkarıldı

👤 Kullanıcı Bilgileri:
• 📎 ID: {user_id}
• 👤 Kullanıcı: {username}
• 📱 Telegram: @{telegram_username}
• 📧 Email: {email}

📋 İşlem Detayları:
• 📝 Sebep: {reason}
• 👮 Çıkaran: {admin}
• ⏰ Tarih: {date}

✨ Kullanıcı tekrar tüm yetkilere sahip
"""

    LOG_SPAM_WARNING = """
⚠️ Spam Uyarısı

👤 Kullanıcı Bilgileri:
• 📎 ID: {user_id}
• 👤 Kullanıcı: {username}
• 📱 Telegram: @{telegram_username}

🚫 Spam Detayları:
• 📝 Tip: {spam_type}
• 🔢 Sayı: {count}
• ⏰ Tarih: {date}
• 🌍 IP: {ip}

⚡ Alınan Önlemler:
• ⚠️ Uyarı verildi
• ⏳ Geçici kısıtlama: {duration}
"""

    LOG_USER_JOIN = """
👋 Yeni Üye Katıldı

👤 Kullanıcı Bilgileri:
• 📎 ID: {user_id}
• 👤 Kullanıcı: {username}
• 📱 Telegram: @{telegram_username}
• 📧 Email: {email}

📅 Katılım Detayları:
• ⏰ Tarih: {date}
• 🌍 IP: {ip}
• 📱 Cihaz: {device}

🔒 Güvenlik Kontrolleri:
• ✅ IP Kontrolü: {ip_status}
• ✅ Hesap Yaşı: {account_age}
• ✅ Profil Durumu: {profile_status}
"""

    LOG_ACCOUNT_LINK = """
🔗 Telegram Hesabı Bağlandı

👤 Kullanıcı Bilgileri:
• 📎 ID: {user_id}
• 👤 Kullanıcı: {username}
• 📧 Email: {email}

📱 Telegram Detayları:
• 🆔 Telegram ID: {telegram_id}
• 👤 Telegram: @{telegram_username}
• 📅 Bağlantı: {date}
• 🌍 IP: {ip}

📊 Hesap Durumu:
• ✨ VIP: {is_vip}
• 🔰 Seviye: {level}
• 📅 Kayıt: {register_date}
"""

    LOG_ACCOUNT_UNLINK = """
❌ Telegram Hesabı Bağlantısı Kesildi

👤 Kullanıcı Bilgileri:
• 📎 ID: {user_id}
• 👤 Kullanıcı: {username}
• 📧 Email: {email}

📱 Eski Telegram Bilgileri:
• 🆔 Telegram ID: {telegram_id}
• 👤 Telegram: @{telegram_username}

📋 İşlem Detayları:
• ⏰ Tarih: {date}
• 🌍 IP: {ip}
• 📝 Sebep: {reason}
"""

    LOG_ADMIN_ACTION = """
👨‍💼 Yönetici İşlemi

🛠️ İşlem Detayları:
• 📝 Tip: {action_type}
• 👮 Yönetici: {admin}
• ⏰ Tarih: {date}
• 🌍 IP: {ip}

👤 Hedef Kullanıcı:
• 📎 ID: {user_id}
• 👤 Kullanıcı: {username}
• 📱 Telegram: @{telegram_username}

📋 İşlem Sonucu:
• ✅ Durum: {status}
• 📝 Not: {notes}
"""

    LOG_SYSTEM_ERROR = """
🚨 Sistem Hatası

❌ Hata Detayları:
• 📝 Tip: {error_type}
• 🔍 Kod: {error_code}
• ⏰ Tarih: {date}
• 🌍 IP: {ip}

👤 İlgili Kullanıcı:
• 📎 ID: {user_id}
• 👤 Kullanıcı: {username}
• 📱 Telegram: @{telegram_username}

🔧 Teknik Detaylar:
{error_details}

⚡ Durum: {status}
"""

    LOG_CODE_USAGE = """
🎁 Kod Kullanımı

👤 Kullanıcı Bilgileri:
• 📎 ID: {user_id}
• 👤 Kullanıcı: {username}
• 📱 Telegram: @{telegram_username}

🎯 Kod Detayları:
• 🔑 Kod: {code}
• 📝 Kategori: {category}
• ⏰ Tarih: {date}
• 🌍 IP: {ip}

📊 Kullanım Durumu:
• ✅ Sonuç: {status}
• 📝 Not: {notes}
"""

    LOG_VIP_STATUS = """
👑 VIP Durum Değişikliği

👤 Kullanıcı Bilgileri:
• 📎 ID: {user_id}
• 👤 Kullanıcı: {username}
• 📱 Telegram: @{telegram_username}

📅 VIP Detayları:
• 🔄 Durum: {status}
• ⏰ Başlangıç: {start_date}
• 🔚 Bitiş: {end_date}
• 💎 Seviye: {level}

📋 İşlem Bilgileri:
• 👮 İşlemi Yapan: {admin}
• 📝 Not: {notes}
• ⏰ Tarih: {date}
""" 