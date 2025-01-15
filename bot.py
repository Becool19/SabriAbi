import os
import asyncio
import logging
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters
import random
import string
from datetime import datetime, timezone
import config
from models import User, TelegramLink
from extensions import db

# Bot logger'ı yapılandır
config.setup_logger('bot')
logger = logging.getLogger('bot')

async def create_application():
    """Bot uygulamasını oluştur ve başlat"""
    try:
        # Bot uygulamasını oluştur
        application = Application.builder().token(config.BOT_TOKEN).build()
        
        # Updater'ı başlat
        await application.initialize()
        
        # Updater'ı durdur (yeniden başlatılacak)
        if application.updater and application.updater.running:
            await application.updater.stop()
        
        print("🤖 Bot handlers eklendi!")
        return application
        
    except Exception as e:
        logger.error(f"Bot oluşturma hatası: {str(e)}")
        raise

async def start(update: Update, context):
    try:
        user = update.effective_user
        config.bot_logger.info(f"Start komutu alındı: {user.id} - @{user.username}")
        
        # Telegram kullanıcı adı kontrolü
        if not user.username:
            warning_message = """⚠️ Telegram Kullanıcı Adı Gerekli!

Sistemimizi kullanabilmek için Telegram kullanıcı adınızın (username) ayarlı olması gerekmektedir.

📝 Nasıl Ayarlanır?
1. Telegram Ayarlar menüsüne gidin
2. "Kullanıcı Adı" seçeneğine tıklayın
3. Kendinize bir kullanıcı adı belirleyin
4. Ayarladıktan sonra tekrar deneyin

❗️ Bu işlemi yapmadan sistemi kullanamazsınız."""
            
            # Log kaydı
            log_message = f"""🚫 Kullanıcı Adı Eksik Erişim Denemesi
            
👤 Kullanıcı: {user.first_name}
🆔 Telegram ID: {user.id}
⚠️ Durum: Kullanıcı adı ayarlanmamış"""
            
            await send_log_message(log_message, "warning")
            await update.message.reply_text(warning_message)
            return

        # Grup üyeliği kontrolü
        try:
            member = await bot.get_chat_member(config.TELEGRAM_GROUP_ID, user.id)
            if member.status in ['left', 'kicked', 'restricted']:
                raise Exception("Grup üyesi değil")
        except Exception as e:
            warning_message = f"""⚠️ Grup Üyeliği Gerekli!

Sistemimizi kullanabilmek için Telegram grubumuza katılmanız gerekmektedir.

📱 Katılmak için:
👉 {config.TELEGRAM_GROUP_LINK}

✅ Gruba katıldıktan sonra tekrar deneyin.

❗️ Bu işlemi yapmadan sistemi kullanamazsınız."""
            
            # Log kaydı
            log_message = f"""🚫 Yetkisiz Erişim Denemesi
            
👤 Kullanıcı: {user.username}
🆔 Telegram ID: {user.id}
⚠️ Durum: Grup üyesi değil"""
            
            await send_log_message(log_message, "warning")
            await update.message.reply_text(warning_message)
            return

        # Kullanıcı adı değişikliği kontrolü
        with app.app_context():
            telegram_link = TelegramLink.query.filter_by(telegram_id=str(user.id)).first()
            if telegram_link and telegram_link.telegram_username != user.username:
                # Log kaydı
                log_message = f"""📝 Telegram Kullanıcı Adı Değişikliği
                
👤 Eski Kullanıcı Adı: @{telegram_link.telegram_username}
👤 Yeni Kullanıcı Adı: @{user.username}
🆔 Telegram ID: {user.id}
📅 Değişiklik Tarihi: {datetime.now(timezone.utc).strftime('%d.%m.%Y %H:%M')}"""
                
                await send_log_message(log_message, "info")
                
                # Website log kaydı
                log_system_event('telegram', telegram_link.user_id, None,
                         f'Telegram kullanıcı adı değiştirildi: @{telegram_link.telegram_username} -> @{user.username}')
                
                # Kullanıcı adını güncelle
                telegram_link.telegram_username = user.username
                db.session.commit()

        # Flask uygulama bağlamını kullan
        from app import app
        with app.app_context():
            # URL'den gelen özel parametreleri kontrol et
            if context.args and len(context.args) > 0:
                user_id = context.args[0]
                try:
                    # Kullanıcıyı veritabanından kontrol et
                    web_user = User.query.get(int(user_id))
                    if not web_user:
                        await update.message.reply_text("Geçersiz kullanıcı ID'si. Lütfen web sitesi üzerinden tekrar deneyin.")
                        return

                    # Doğrulama kodunu oluştur
                    verification_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
                    logger.info(f"Doğrulama kodu oluşturuldu: {user_id} - {verification_code}")
                    
                    # Mevcut bağlantıyı kontrol et veya yeni oluştur
                    telegram_link = TelegramLink.query.filter_by(user_id=user_id).first()
                    if telegram_link:
                        telegram_link.telegram_id = str(user.id)
                        telegram_link.telegram_username = user.username
                        telegram_link.verification_code = verification_code
                        telegram_link.is_verified = False
                    else:
                        telegram_link = TelegramLink(
                            user_id=user_id,
                            telegram_id=str(user.id),
                            telegram_username=user.username,
                            verification_code=verification_code,
                            is_verified=False
                        )
                        db.session.add(telegram_link)
                    
                    db.session.commit()

                    # Hoş geldin mesajı gönder
                    welcome_message = f"""Merhaba {user.first_name}!

SabriAbiBot'a hoş geldiniz! Size özel avantajlardan yararlanmak için hesabınızı doğrulamanız gerekiyor.

Doğrulama Kodunuz: {verification_code}

Bu kodu web sitesindeki ilgili alana girerek hesabınızı hemen doğrulayabilirsiniz."""

                    await update.message.reply_text(welcome_message)
                    logger.info(f"Hoş geldin mesajı gönderildi: {user_id}")

                    # Log gönder
                    log_message = f"""Bot Başlatıldı:
👤 Kullanıcı: {user.username}
🆔 Telegram ID: {user.id}
🔗 Start Parametresi: {context.args[0] if context.args else 'Yok'}"""
                    await send_log_message(log_message, "info")

                except Exception as e:
                    logger.error(f"Start komutu hatası: {str(e)}")
                    await update.message.reply_text("Bir hata oluştu. Lütfen daha sonra tekrar deneyin.")
            else:
                # Normal karşılama mesajı
                await update.message.reply_text(f"Merhaba {user.first_name}!\n\nBu bot sadece web sitemiz üzerinden hesap doğrulaması için kullanılmaktadır.")
                logger.info(f"Normal karşılama mesajı gönderildi: {user.id}")
    except Exception as e:
        logger.error(f"Start komutu genel hatası: {str(e)}")
        if update and update.message:
            await update.message.reply_text("Bir hata oluştu. Lütfen daha sonra tekrar deneyin.")

async def help(update: Update, context):
    help_message = """🤖 Bot Komutları:

/start - Botu başlatır
/help - Bu yardım mesajını gösterir
/link - Hesap bağlama kodunu yeniler

📌 Nasıl Kullanılır?
1. Web sitemize giriş yapın
2. Profil sayfasında "Telegram Bağla" butonuna tıklayın
3. Size verilen doğrulama kodunu girin
4. İşlem tamamlandığında bildirim alacaksınız

⚠️ Önemli Notlar:
• Her kod tek kullanımlıktır
• Kodlar 10 dakika geçerlidir
• Sorun yaşarsanız /link ile yeni kod alabilirsiniz

🎮 İyi oyunlar!"""
    
    await update.message.reply_text(help_message)

async def link_account(update: Update, context):
    user = update.effective_user
    telegram_id = str(user.id)
    
    # Bağlı hesabı kontrol et
    link = TelegramLink.query.filter_by(telegram_id=telegram_id).first()
    if link and link.is_verified:
        user_data = User.query.get(link.user_id)
        success_message = f"""✅ Telegram Hesabı Zaten Bağlı!

🎯 Bağlantı Detayları:
• 👤 Kullanıcı: {user_data.username}
• 📱 Telegram: @{user.username}
• 📅 Tarih: {datetime.now(timezone.utc).strftime("%d.%m.%Y %H:%M")}

🎮 Tüm özellikleri kullanabilirsiniz!"""
        await update.message.reply_text(success_message)
        return

    # Yeni doğrulama kodu oluştur
    verification_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    
    # Mevcut bağlantıyı güncelle veya yeni bağlantı oluştur
    if link:
        link.verification_code = verification_code
    else:
        link = TelegramLink(
            telegram_id=telegram_id,
            telegram_username=user.username,
            verification_code=verification_code
        )
        db.session.add(link)
    
    db.session.commit()
    
    instructions_message = f"""🔄 Yeni Doğrulama Kodu Oluşturuldu!

🔐 Doğrulama Kodunuz: {verification_code}

📌 Nasıl Kullanılır?
1. Web sitemize giriş yapın
2. Profil sayfasında "Telegram Bağla" bölümüne gidin
3. Bu kodu ilgili alana girin

⚠️ Önemli Notlar:
• Kod 10 dakika süreyle geçerlidir
• Büyük harf ve rakamlardan oluşur
• Tek kullanımlıktır

🎮 İyi oyunlar!"""
    await update.message.reply_text(instructions_message)

async def handle_message(update: Update, context):
    try:
        if update.message and update.message.text:
            user = update.effective_user
            logger.info(f"Gelen mesaj: {user.id} - {update.message.text}")
            
            if update.message.text.startswith('/'):
                command = update.message.text.split()[0].lower()
                if command == '/start':
                    await start(update, context)
                elif command == '/help':
                    await help(update, context)
                elif command == '/link':
                    await link_account(update, context)
            else:
                await update.message.reply_text("Komut bulunamadı. Kullanılabilir komutlar için /help yazın.")
    except Exception as e:
        logger.error(f"Mesaj işleme hatası: {str(e)}")
        if update and update.message:
            await update.message.reply_text("Bir hata oluştu. Lütfen daha sonra tekrar deneyin.")

async def error_handler(update: Update, context):
    logger.error(f"Bot hatası: {context.error}")
    if update and update.message:
        await update.message.reply_text("Bir hata oluştu. Lütfen daha sonra tekrar deneyin.") 

def setup_bot_handlers(application):
    """Bot komutlarını ve handler'larını ekle"""
    try:
        # Önce mevcut handler'ları temizle
        if hasattr(application, 'handlers'):
            application.handlers.clear()
        if hasattr(application, 'error_handlers'):
            application.error_handlers.clear()
        
        # Komut işleyicileri
        application.add_handler(CommandHandler("start", start))
        application.add_handler(CommandHandler("help", help))
        application.add_handler(CommandHandler("link", link_account))
        
        # Genel mesaj işleyici
        application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
        
        # Hata işleyici
        application.add_error_handler(error_handler)
        
        print("🤖 Bot handlers eklendi!")
        
    except Exception as e:
        logger.error(f"Handler ekleme hatası: {str(e)}")
        raise 