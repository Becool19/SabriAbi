import os
from flask import Flask, render_template, request, redirect, url_for, flash, abort, jsonify, send_file, Response
from flask_login import login_user, logout_user, login_required, current_user
from functools import wraps
from datetime import datetime, timezone, timedelta
from messages import Messages
from telegram.ext import Application, CommandHandler, MessageHandler, filters
from telegram import Update, Bot
import random
import string
import asyncio
import requests
from io import StringIO
import csv
import json
from werkzeug.security import generate_password_hash, check_password_hash
import config
import logging

# Extensions'ı import et
from extensions import db, login_manager, migrate

# Instance klasörünü oluştur
instance_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance')
if not os.path.exists(instance_path):
    os.makedirs(instance_path)

# Flask app konfigürasyonu
app = Flask(__name__, instance_relative_config=True)
app.config['SECRET_KEY'] = config.SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = config.DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Extensions'ları initialize et
db.init_app(app)
login_manager.init_app(app)
migrate.init_app(app, db)

# Modelleri import et
from models import User, GiftCode, SpecialCode, CodeUsageLog, TelegramLink, SystemLog

# Bot uygulamasını oluştur
from bot import create_application

# Global bir değişken olarak bot uygulamasını tanımla
bot_app = None

# Bot nesnesini oluşturun
bot = Bot(token=config.BOT_TOKEN)

# Telegram bot komutları
async def start(update: Update, context):
    try:
        user = update.effective_user
        logging.info(f"Start komutu alındı: {user.id} - @{user.username}")
        
        # URL'den gelen özel parametreleri kontrol et
        if context.args and len(context.args) > 0:
            user_id = context.args[0]
            try:
                # Kullanıcıyı veritabanından kontrol et
                with app.app_context():
                    web_user = User.query.get(int(user_id))
                    if not web_user:
                        await update.message.reply_text("Geçersiz kullanıcı ID'si. Lütfen web sitesi üzerinden tekrar deneyin.")
                        return

                    # Doğrulama kodunu oluştur
                    verification_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
                    logging.info(f"Doğrulama kodu oluşturuldu: {user_id} - {verification_code}")
                    
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

                    # Hoş geldin mesajı
                    welcome_message = f"""Merhaba {user.first_name}!

VIP Casino dünyasına hoş geldiniz! Size özel avantajlardan yararlanmak için hesabınızı doğrulamanız gerekiyor.

Doğrulama Kodunuz: {verification_code}

Bu kodu web sitesindeki ilgili alana girerek hesabınızı hemen doğrulayabilirsiniz.

Önemli Bilgiler:
• Kod 10 dakika süreyle geçerlidir
• Büyük harf ve rakamlardan oluşur
• Tek kullanımlıktır

Doğrulama sonrası size özel:
• Günlük hediye kodları
• Özel bonuslar
• VIP etkinlikler
• 7/24 destek

Hemen doğrulayın ve ayrıcalıklı dünyamıza katılın!"""

                    await update.message.reply_text(welcome_message)
                    
                    # Log gönder
                    send_log(f"Yeni doğrulama kodu oluşturuldu:\nKullanıcı: {user.username}\nKod: {verification_code}")
                    
                    logging.info(f"Hoş geldin mesajı gönderildi: {user_id}")
            except Exception as e:
                logging.error(f"Start komutu hatası: {str(e)}")
                await update.message.reply_text("Bir hata oluştu. Lütfen daha sonra tekrar deneyin.")
        else:
            # Normal karşılama mesajı
            await update.message.reply_text(f"""Merhaba {user.first_name}!

Bu bot sadece web sitemiz üzerinden hesap doğrulaması için kullanılmaktadır.

Sitemize giriş yapın ve Telegram bağlantısı bölümünden hesabınızı doğrulayın.

📢 Telegram Grubumuz: {config.TELEGRAM_GROUP_LINK}

Yardıma mı ihtiyacınız var?
/help yazarak komutlar hakkında bilgi alabilirsiniz.""")
            logging.info(f"Normal karşılama mesajı gönderildi: {user.id}")
    except Exception as e:
        logging.error(f"Start komutu genel hatası: {str(e)}")
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
    with app.app_context():
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
                verification_code=verification_code,
                is_verified=False
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

# Bot handler'larını eklemek için bir fonksiyon oluştur
def setup_bot_handlers(application):
    # Komut işleyicileri
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help))
    application.add_handler(CommandHandler("link", link_account))
    
    # Genel mesaj işleyici
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    
    # Hata işleyici
    application.add_error_handler(error_handler)
    
    print("🤖 Bot handlers eklendi!")

# Genel mesaj işleyici
async def handle_message(update: Update, context):
    try:
        if update.message and update.message.text:
            user = update.effective_user
            logging.info(f"Gelen mesaj: {user.id} - {update.message.text}")
            
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
        logging.error(f"Mesaj işleme hatası: {str(e)}")
        if update and update.message:
            await update.message.reply_text("Bir hata oluştu. Lütfen daha sonra tekrar deneyin.")

# Hata işleyici
async def error_handler(update: Update, context):
    logging.error(f"Bot hatası: {context.error}")
    if update and update.message:
        await update.message.reply_text("Bir hata oluştu. Lütfen daha sonra tekrar deneyin.")

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            if not current_user.is_authenticated:
                print("Kullanıcı giriş yapmamış")  # Debug log
                flash('Lütfen önce giriş yapın.', 'warning')
                return redirect(url_for('login'))
                
            print(f"Kullanıcı yetkileri: is_admin={current_user.is_admin}")  # Debug log
            
            if not current_user.is_admin:
                print(f"Yetkisiz erişim denemesi: {current_user.username}")  # Debug log
                flash('Bu sayfaya erişim yetkiniz yok.', 'danger')
                return redirect(url_for('dashboard'))
                
            return f(*args, **kwargs)
            
        except Exception as e:
            print(f"Admin decorator hatası: {str(e)}")  # Hata detayını yazdır
            import traceback
            traceback.print_exc()  # Tam hata stack'ini yazdır
            flash('Bir hata oluştu: ' + str(e), 'error')
            return redirect(url_for('dashboard'))
            
    return decorated_function

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Database oluştur
with app.app_context():
    db.create_all()
    
    # İlk admin kullanıcısını oluştur (eğer yoksa)
    admin_user = User.query.filter_by(is_admin=True).first()
    if not admin_user:
        hashed_password = generate_password_hash('muharrem')
        admin = User(
            username='becool',
            email='admin@example.com',
            password=hashed_password,
            is_admin=True,
            is_active=True,
            approval_status='approved',
            approval_date=datetime.now(timezone.utc),
            betgit_id='ADMIN',
            hasbet_id='ADMIN'
        )
        db.session.add(admin)
        db.session.commit()
        print("Admin kullanıcısı oluşturuldu!")

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            # Hesap durumunu kontrol et
            if user.approval_status == 'approved' or user.is_admin:
                login_user(user)
                
                # Giriş logunu kaydet
                log_system_event('login', user.id, request.remote_addr,
                         f'Başarılı giriş: {user.username}')
                
                return redirect(url_for('dashboard'))
            elif user.approval_status == 'pending':
                flash('Hesabınız henüz onaylanmadı. Lütfen onay için bekleyin.', 'warning')
            elif user.approval_status == 'rejected':
                flash('Hesabınız reddedildi. Detaylı bilgi için yöneticiyle iletişime geçin.', 'error')
            else:
                flash('Hesabınız aktif değil.', 'error')
        else:
            flash('Geçersiz kullanıcı adı veya şifre.', 'error')
            
        return redirect(url_for('login'))
        
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        betgit_id = request.form.get('betgit_id')
        hasbet_id = request.form.get('hasbet_id')
        special_code = request.form.get('special_code')

        # Kullanıcı adı ve email kontrolü
        if User.query.filter_by(username=username).first():
            flash('Bu kullanıcı adı zaten kullanılıyor.', 'error')
            return redirect(url_for('register'))
            
        if User.query.filter_by(email=email).first():
            flash('Bu email adresi zaten kullanılıyor.', 'error')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        new_user = User(
            username=username,
            email=email,
            password=hashed_password,
            betgit_id=betgit_id,
            hasbet_id=hasbet_id,
            special_code=special_code,
            registration_date=datetime.now(timezone.utc),
            registration_ip=request.remote_addr,
            approval_status='pending',  # Varsayılan olarak onay bekliyor
            is_active=True  # Aktif olarak başlat
        )

        try:
            db.session.add(new_user)
            db.session.commit()
            
            # Kayıt logunu gönder
            log_message = format_registration_log(new_user)
            send_log(log_message, "info")
            
            flash('Hesabınız oluşturuldu! Admin onayından sonra giriş yapabilirsiniz.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('Kayıt sırasında bir hata oluştu. Lütfen daha sonra tekrar deneyin.', 'error')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.approval_status == 'pending':
        return redirect(url_for('pending_approval'))
    elif current_user.approval_status == 'rejected':
        flash('Hesabınız reddedildi.', 'danger')
        return redirect(url_for('login'))
    
    # Kullanıcının son kod kullanımları
    recent_codes = CodeUsageLog.query.filter_by(user_id=current_user.id)\
                      .order_by(CodeUsageLog.timestamp.desc())\
                      .limit(5).all()
    
    return render_template('dashboard.html',
                         user=current_user,
                         recent_codes=recent_codes)

@app.route('/admin')
@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    try:
        # İstatistikleri hesapla
        stats = {
            'total_users': User.query.count(),
            'active_users': User.query.filter_by(is_active=True).count(),
            'pending_users': User.query.filter_by(approval_status='pending').count(),
            'blacklisted_users': User.query.filter(User.blacklist_reason.isnot(None)).count(),
            'total_codes': GiftCode.query.count(),
            'active_codes': GiftCode.query.filter_by(is_active=True).count(),
            'total_logs': SystemLog.query.count()
        }
        
        # Son işlemleri al
        recent_users = User.query.order_by(User.registration_date.desc()).limit(5).all()
        recent_codes = GiftCode.query.order_by(GiftCode.created_at.desc()).limit(5).all()
        recent_logs = SystemLog.query.order_by(SystemLog.timestamp.desc()).limit(5).all()
        
        print("Admin dashboard verileri hazırlandı:", stats)  # Debug log
        
        return render_template('admin/dashboard.html',
                             stats=stats,
                             recent_users=recent_users,
                             recent_codes=recent_codes,
                             recent_logs=recent_logs)
                             
    except Exception as e:
        print(f"Admin dashboard hatası: {str(e)}")  # Hata detayını yazdır
        import traceback
        traceback.print_exc()  # Tam hata stack'ini yazdır
        flash('Bir hata oluştu: ' + str(e), 'error')
        return redirect(url_for('dashboard'))

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    pagination = User.query.order_by(User.registration_date.desc()).paginate(
        page=page, per_page=per_page, error_out=False)
    users = pagination.items
    return render_template('admin/users.html', 
                         users=users,
                         pagination=pagination,
                         total_pages=pagination.pages,
                         current_page=page)

@app.route('/admin/gift-codes')
@login_required
@admin_required
def admin_gift_codes():
    gift_codes = GiftCode.query.filter_by(category='hediye_kodu')\
        .order_by(GiftCode.created_at.desc()).all()
    return render_template('admin/gift_codes.html', gift_codes=gift_codes)

@app.route('/admin/special-codes')
@login_required
@admin_required
def admin_special_codes():
    special_codes = SpecialCode.query.order_by(SpecialCode.created_at.desc()).all()
    return render_template('admin/special_codes.html', special_codes=special_codes)

@app.route('/admin/logs')
@login_required
@admin_required
def admin_logs():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 50
        
        # Filtreleri al
        event_type = request.args.get('event_type')
        user_filter = request.args.get('user')
        ip_filter = request.args.get('ip')
        importance = request.args.get('importance')
        date_filter = request.args.get('date')
        
        # Query oluştur
        query = SystemLog.query
        
        if event_type:
            query = query.filter_by(event_type=event_type)
        if user_filter:
            query = query.join(User).filter(User.username.ilike(f'%{user_filter}%'))
        if ip_filter:
            query = query.filter(SystemLog.ip_address.ilike(f'%{ip_filter}%'))
        if importance:
            query = query.filter_by(importance=importance)
        if date_filter:
            date_obj = datetime.strptime(date_filter, '%Y-%m-%d')
            query = query.filter(
                db.func.date(SystemLog.timestamp) == date_obj.date()
            )
        
        # Sıralama ve sayfalama
        pagination = query.order_by(SystemLog.timestamp.desc())\
            .paginate(page=page, per_page=per_page, error_out=False)
        
        logs = pagination.items
        
        # Debug için
        print(f"Toplam log sayısı: {len(logs)}")
        for log in logs:
            print(f"Log ID: {log.id}, User ID: {log.user_id}, User: {log.user.username if log.user else 'Silinmiş'}")
        
        return render_template('admin/logs.html', 
                             logs=logs,
                             pagination=pagination)
                             
    except Exception as e:
        print(f"Log sayfası hatası: {str(e)}")
        import traceback
        traceback.print_exc()
        flash('Bir hata oluştu: ' + str(e), 'error')
        return redirect(url_for('dashboard'))

@app.route('/api/admin/logs/export')
@login_required
@admin_required
def export_logs():
    format = request.args.get('format', 'csv')
    
    # Logları al
    logs = SystemLog.query.order_by(SystemLog.timestamp.desc()).all()
    
    if format == 'csv':
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['Tarih', 'Olay Tipi', 'Kullanıcı', 'IP', 'Detay', 'Önem'])
        
        for log in logs:
            writer.writerow([
                log.timestamp.strftime('%d.%m.%Y %H:%M:%S'),
                log.event_type,
                User.query.get(log.user_id).username if log.user_id else 'Sistem',
                log.ip_address,
                log.details,
                log.importance
            ])
        
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment;filename=logs.csv'}
        )
    
    elif format == 'json':
        logs_data = [{
            'timestamp': log.timestamp.strftime('%d.%m.%Y %H:%M:%S'),
            'event_type': log.event_type,
            'user': User.query.get(log.user_id).username if log.user_id else 'Sistem',
            'ip_address': log.ip_address,
            'details': log.details,
            'importance': log.importance
        } for log in logs]
        
        return jsonify(logs_data)

@app.route('/admin/blacklist')
@login_required
@admin_required
def admin_blacklist():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    pagination = User.query.filter(User.blacklist_reason.isnot(None)).paginate(
        page=page, per_page=per_page, error_out=False)
    blacklisted_users = pagination.items
    return render_template('admin/blacklist.html', 
                         users=blacklisted_users,
                         pagination=pagination,
                         total_pages=pagination.pages,
                         current_page=page)

# Admin API routes
@app.route('/api/admin/user/<int:user_id>/approve', methods=['POST'])
@admin_required
def approve_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        user.is_approved = True
        user.approval_status = 'approved'
        user.approval_date = datetime.utcnow()
        db.session.commit()
        
        log_system_event('admin', current_user.id, request.remote_addr,
                 f'Kullanıcı onaylandı: {user.username} (ID: {user.id})')
        
        return jsonify({'success': True, 'message': 'Kullanıcı başarıyla onaylandı'})
    except Exception as e:
        db.session.rollback()
        log_system_event('admin', current_user.id, request.remote_addr,
                 f'Kullanıcı onaylama hatası: {str(e)}', 'ERROR')
        return jsonify({'success': False, 'message': 'Kullanıcı onaylanırken bir hata oluştu'}), 500

@app.route('/api/admin/user/<int:user_id>/reject', methods=['POST'])
@admin_required
def reject_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.approval_status == 'rejected':
        return jsonify({'success': False, 'message': 'Kullanıcı zaten reddedilmiş.'})
    
    data = request.json
    reason = data.get('reason', 'Belirtilmedi')
    
    user.approval_status = 'rejected'
    user.rejection_reason = reason
    user.rejected_by_id = current_user.id
    user.rejected_at = datetime.now(timezone.utc)
    
    # Kara listeye alma
    if data.get('blacklist', False):
        user.blacklist_reason = f"Kayıt reddi: {reason}"
        user.blacklisted_by_id = current_user.id
        user.blacklisted_at = datetime.now(timezone.utc)
    
    # Log kaydı
    log_system_event('admin', current_user.id, request.remote_addr,
             f'Kullanıcı reddedildi: {user.username} (Sebep: {reason})', 'warning')
    
    db.session.commit()
    
    # Telegram bildirimi
    telegram_link = TelegramLink.query.filter_by(user_id=user.id).first()
    if telegram_link:
        try:
            bot.send_message(
                chat_id=telegram_link.telegram_id,
                text=f"❌ Hesabınız reddedildi.\n\nSebep: {reason}\n\nDaha fazla bilgi için lütfen yöneticilerle iletişime geçin."
            )
        except Exception as e:
            log_system_event('telegram', None, request.remote_addr,
                     f'Telegram mesajı gönderilemedi: {str(e)}', 'error')
    
    return jsonify({'success': True})

@app.route('/api/admin/user/<int:user_id>/blacklist', methods=['POST'])
@admin_required
def blacklist_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.blacklist_reason:
        return jsonify({'success': False, 'message': 'Kullanıcı zaten kara listede.'})
    
    data = request.json
    reason = data.get('reason', 'Belirtilmedi')
    permanent = data.get('permanent', False)
    
    user.blacklist_reason = reason
    user.blacklisted_by_id = current_user.id
    user.blacklisted_at = datetime.now(timezone.utc)
    
    if permanent:
        user.is_active = False
    
    # Log kaydı
    log_system_event('admin', current_user.id, request.remote_addr,
             f'Kullanıcı kara listeye alındı: {user.username} (Sebep: {reason})', 'warning')
    
    db.session.commit()
    
    # Telegram bildirimi
    if data.get('notify_telegram', False):
        telegram_link = TelegramLink.query.filter_by(user_id=user.id).first()
        if telegram_link:
            try:
                bot.send_message(
                    chat_id=telegram_link.telegram_id,
                    text=f"⛔️ Hesabınız kara listeye alındı.\n\nSebep: {reason}\n\nDaha fazla bilgi için lütfen yöneticilerle iletişime geçin."
                )
            except Exception as e:
                log_system_event('telegram', None, request.remote_addr,
                         f'Telegram mesajı gönderilemedi: {str(e)}', 'error')
    
    return jsonify({'success': True})

@app.route('/api/admin/user/<int:user_id>/remove-blacklist', methods=['POST'])
@admin_required
def remove_from_blacklist(user_id):
    user = User.query.get_or_404(user_id)
    if not user.blacklist_reason:
        return jsonify({'success': False, 'message': 'Kullanıcı kara listede değil.'})
    
    old_reason = user.blacklist_reason
    user.blacklist_reason = None
    user.blacklisted_by_id = None
    user.blacklisted_at = None
    user.is_active = True
    
    # Log kaydı
    log_system_event('admin', current_user.id, request.remote_addr,
             f'Kullanıcı kara listeden çıkarıldı: {user.username} (Eski sebep: {old_reason})', 'info')
    
    db.session.commit()
    
    # Telegram bildirimi
    telegram_link = TelegramLink.query.filter_by(user_id=user.id).first()
    if telegram_link:
        try:
            bot.send_message(
                chat_id=telegram_link.telegram_id,
                text=f"✅ Hesabınız kara listeden çıkarıldı.\n\nArtık sistemimizi tekrar kullanabilirsiniz."
            )
        except Exception as e:
            log_system_event('telegram', None, request.remote_addr,
                     f'Telegram mesajı gönderilemedi: {str(e)}', 'error')
    
    return jsonify({'success': True})

@app.route('/api/admin/code/create', methods=['POST'])
@admin_required
def create_code():
    data = request.json
    
    # Kod oluşturma
    code = GiftCode(
        code=data['code'],
        type=data['type'],
        category=data.get('category'),
        max_uses=data.get('max_uses', 1),
        amount=data.get('amount'),
        expires_at=datetime.strptime(data['expires_at'], '%Y-%m-%d').replace(tzinfo=timezone.utc) if data.get('expires_at') else None,
        notes=data.get('notes'),
        created_by_id=current_user.id
    )
    
    db.session.add(code)
    
    # Log kaydı
    log_system_event('admin', current_user.id, request.remote_addr,
             f'Yeni kod oluşturuldu: {code.code} ({code.type})', 'info')
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'code': {
            'id': code.id,
            'code': code.code,
            'type': code.type,
            'category': code.category,
            'max_uses': code.max_uses,
            'amount': code.amount,
            'expires_at': code.expires_at.strftime('%d.%m.%Y') if code.expires_at else None,
            'notes': code.notes
        }
    })

@app.route('/api/admin/ip-info/<ip>', methods=['GET'])
@admin_required
def get_ip_info(ip):
    try:
        # IP-API'den bilgileri al
        response = requests.get(f'http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting,query')
        data = response.json()
        
        if data['status'] == 'success':
            # Risk skorunu hesapla
            risk_score = 0
            risk_factors = []
            
            # Proxy/VPN kontrolü
            if data.get('proxy', False):
                risk_score += 50
                risk_factors.append('Proxy/VPN Kullanımı')
            
            # Hosting/Datacenter kontrolü
            if data.get('hosting', False):
                risk_score += 30
                risk_factors.append('Hosting/Datacenter IP')
            
            # Mobil ağ kontrolü
            if data.get('mobile', False):
                risk_score += 10
                risk_factors.append('Mobil Ağ')

            # Ülke bazlı risk
            high_risk_countries = ['RU', 'CN', 'KP', 'IR']  # Örnek yüksek riskli ülkeler
            if data.get('countryCode') in high_risk_countries:
                risk_score += 20
                risk_factors.append('Riskli Ülke')

            return jsonify({
                'ip': data['query'],
                'country': data['country'],
                'countryCode': data['countryCode'],
                'region': data['regionName'],
                'city': data['city'],
                'isp': data['isp'],
                'org': data.get('org', 'Bilinmiyor'),
                'timezone': data['timezone'],
                'location': {
                    'lat': data['lat'],
                    'lon': data['lon']
                },
                'security': {
                    'risk_score': risk_score,
                    'risk_factors': risk_factors,
                    'proxy': data.get('proxy', False),
                    'hosting': data.get('hosting', False),
                    'mobile': data.get('mobile', False)
                }
            })
        else:
            return jsonify({
                'error': 'IP bilgileri alınamadı',
                'message': data.get('message', 'Bilinmeyen hata')
            }), 404
            
    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 500

# User Routes
@app.route('/pending')
@login_required
def pending_approval():
    if current_user.approval_status != 'pending':
        return redirect(url_for('dashboard'))
    return render_template('pending_approval.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Başarıyla çıkış yaptınız.', 'success')
    return redirect(url_for('login'))

@app.route('/start_telegram_auth')
@login_required
def start_telegram_auth():
    try:
        # Telegram bot linki oluştur
        bot_link = f"https://t.me/foolingaround_bot?start={current_user.id}"
        
        # AJAX isteği ise JSON yanıt döndür
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'success': True,
                'bot_link': bot_link
            })
            
        # Normal istek ise yönlendirme yap
        return redirect(bot_link)
        
    except Exception as e:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'success': False,
                'message': 'Bir hata oluştu. Lütfen daha sonra tekrar deneyin.'
            })
        flash('Bir hata oluştu. Lütfen daha sonra tekrar deneyin.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/verify_telegram', methods=['POST'])
@login_required
def verify_telegram():
    try:
        data = request.json
        code = data.get('code')
        
        if not code:
            return jsonify({
                'success': False,
                'message': 'Doğrulama kodu gerekli.'
            }), 400
            
        # Doğrulama kodunu kontrol et
        telegram_link = TelegramLink.query.filter_by(
            verification_code=code,
            is_verified=False
        ).first()
        
        if not telegram_link:
            return jsonify({
                'success': False,
                'message': 'Geçersiz doğrulama kodu.'
            }), 400
            
        # Telegram hesabını doğrula
        telegram_link.is_verified = True
        telegram_link.verified_at = datetime.now(timezone.utc)
        telegram_link.user_id = current_user.id
        
        # Kullanıcı bilgilerini güncelle
        current_user.telegram_id = telegram_link.telegram_id
        current_user.telegram_username = telegram_link.telegram_username
        current_user.telegram_verified = True
        
        db.session.commit()
        
        # Telegram bağlantı logunu gönder
        log_message = format_telegram_link_log(current_user, telegram_link)
        send_log(log_message, "success")
        
        # Telegram'a bildirim gönder
        try:
            bot.send_message(
                chat_id=telegram_link.telegram_id,
                text=f"""✅ Hesabınız Başarıyla Doğrulandı!

🎯 Bağlantı Detayları:
• 👤 Kullanıcı: {current_user.username}
• 📱 Telegram: @{telegram_link.telegram_username}
• 📅 Tarih: {datetime.now(timezone.utc).strftime('%d.%m.%Y %H:%M')}

🎮 Artık tüm özellikleri kullanabilirsiniz!"""
            )
        except Exception as e:
            print(f"Telegram mesaj hatası: {str(e)}")
        
        return jsonify({
            'success': True,
            'message': 'Telegram hesabınız başarıyla doğrulandı!'
        })
        
    except Exception as e:
        print(f"Doğrulama hatası: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Bir hata oluştu. Lütfen daha sonra tekrar deneyin.'
        }), 500

def log_system_event(event_type, user_id=None, details=None, importance='low', status='success'):
    try:
        log = SystemLog(
            event_type=event_type,
            user_id=user_id,
            ip_address=request.remote_addr,
            details=details,
            importance=importance,
            status=status
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        print(f"Log kayıt hatası: {str(e)}")
        db.session.rollback()

# Blacklist API Routes
@app.route('/api/admin/blacklist/add-user', methods=['POST'])
@login_required
@admin_required
def blacklist_add_user():
    try:
        username = request.form.get('username')
        reason = request.form.get('reason')

        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({
                'success': False,
                'message': 'Kullanıcı bulunamadı.'
            }), 404

        if user.blacklist_reason:
            return jsonify({
                'success': False,
                'message': 'Kullanıcı zaten kara listede.'
            }), 400

        user.blacklist_reason = reason
        user.blacklisted_at = datetime.now(timezone.utc)
        user.blacklisted_by_id = current_user.id
        
        db.session.commit()

        log_system_event('blacklist', current_user.id, request.remote_addr,
                 f'Kullanıcı kara listeye eklendi: {username} (Sebep: {reason})')

        return jsonify({
            'success': True,
            'message': 'Kullanıcı başarıyla kara listeye eklendi.'
        })

    except Exception as e:
        db.session.rollback()
        log_system_event('blacklist', current_user.id, request.remote_addr,
                 f'Kara liste ekleme hatası: {str(e)}', 'ERROR')
        return jsonify({
            'success': False,
            'message': 'Bir hata oluştu.'
        }), 500

@app.route('/api/admin/blacklist/add-telegram-user', methods=['POST'])
@login_required
@admin_required
def blacklist_add_telegram_user():
    try:
        telegram_identifier = request.form.get('telegram_identifier')
        reason = request.form.get('reason')

        user = None
        if telegram_identifier.isdigit():
            user = User.query.filter_by(telegram_id=telegram_identifier).first()
        else:
            user = User.query.filter_by(telegram_username=telegram_identifier.lstrip('@')).first()

        if not user:
            return jsonify({
                'success': False,
                'message': 'Telegram kullanıcısı bulunamadı.'
            }), 404

        if user.blacklist_reason:
            return jsonify({
                'success': False,
                'message': 'Kullanıcı zaten kara listede.'
            }), 400

        user.blacklist_reason = reason
        user.blacklisted_at = datetime.now(timezone.utc)
        user.blacklisted_by_id = current_user.id
        
        db.session.commit()

        log_system_event('blacklist', current_user.id, request.remote_addr,
                 f'Telegram kullanıcısı kara listeye eklendi: {telegram_identifier} (Sebep: {reason})')

        return jsonify({
            'success': True,
            'message': 'Kullanıcı başarıyla kara listeye eklendi.'
        })

    except Exception as e:
        db.session.rollback()
        log_system_event('blacklist', current_user.id, request.remote_addr,
                 f'Telegram kara liste ekleme hatası: {str(e)}', 'ERROR')
        return jsonify({
            'success': False,
            'message': 'Bir hata oluştu.'
        }), 500

@app.route('/api/admin/blacklist/remove-user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def blacklist_remove_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        
        if not user.blacklist_reason:
            return jsonify({
                'success': False,
                'message': 'Kullanıcı zaten kara listede değil.'
            }), 400

        user.blacklist_reason = None
        user.blacklisted_at = None
        user.blacklisted_by_id = None
        
        db.session.commit()

        log_system_event('blacklist', current_user.id, request.remote_addr,
                 f'Kullanıcı kara listeden çıkarıldı: {user.username}')

        return jsonify({
            'success': True,
            'message': 'Kullanıcı başarıyla kara listeden çıkarıldı.'
        })

    except Exception as e:
        db.session.rollback()
        log_system_event('blacklist', current_user.id, request.remote_addr,
                 f'Kara listeden çıkarma hatası: {str(e)}', 'ERROR')
        return jsonify({
            'success': False,
            'message': 'Bir hata oluştu.'
        }), 500

@app.route('/api/admin/codes/add-gift-codes', methods=['POST'])
@login_required
@admin_required
def add_gift_codes():
    try:
        platform = request.form.get('platform')
        max_uses = int(request.form.get('max_uses'))
        expires_at = datetime.strptime(request.form.get('expires_at'), '%Y-%m-%dT%H:%M')
        codes = request.form.get('codes').split('\n')
        
        added_codes = []
        for code in codes:
            code = code.strip()
            if code:
                gift_code = GiftCode(
                    code=code,
                    platform=platform,
                    max_uses=max_uses,
                    expires_at=expires_at,
                    created_by_id=current_user.id
                )
                db.session.add(gift_code)
                added_codes.append(code)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'{len(added_codes)} kod başarıyla eklendi'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.route('/api/admin/codes/add-special-code', methods=['POST'])
@login_required
@admin_required
def add_special_code():
    try:
        data = request.form.get('code')
        category = request.form.get('category')
        max_uses = int(request.form.get('max_uses'))
        expires_at = datetime.strptime(request.form.get('expires_at'), '%Y-%m-%dT%H:%M')
        notes = request.form.get('notes')
        
        special_code = SpecialCode(
            code=code,
            category=category,
            max_uses=max_uses,
            expires_at=expires_at,
            notes=notes,
            created_by_id=current_user.id
        )
        
        db.session.add(special_code)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Özel kod başarıyla eklendi'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.route('/api/admin/codes/details/<int:code_id>')
@login_required
@admin_required
def get_code_details(code_id):
    try:
        code = GiftCode.query.get_or_404(code_id)
        users = CodeUsageLog.query.filter_by(code=code.code).all()
        
        return jsonify({
            'code': code.code,
            'status': 'Aktif' if code.is_active else 'Pasif',
            'created_at': code.created_at.strftime('%d.%m.%Y %H:%M'),
            'expires_at': code.expires_at.strftime('%d.%m.%Y %H:%M'),
            'users': [{
                'username': User.query.get(log.user_id).username,
                'used_at': log.timestamp.strftime('%d.%m.%Y %H:%M')
            } for log in users]
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.route('/api/admin/user/<int:user_id>/details')
@login_required
@admin_required
def get_user_details(user_id):
    try:
        user = User.query.get_or_404(user_id)
        
        return jsonify({
            'success': True,
            'user': {
                'username': user.username,
                'email': user.email,
                'registration_date': user.registration_date.strftime('%d.%m.%Y %H:%M'),
                'last_login': user.last_login.strftime('%d.%m.%Y %H:%M') if user.last_login else None,
                'telegram_username': user.telegram_username,
                'telegram_id': user.telegram_id,
                'telegram_verified': user.telegram_verified,
                'betgit_id': user.betgit_id,
                'hasbet_id': user.hasbet_id,
                'last_ip': user.last_ip,
                'registration_ip': user.registration_ip,
                'is_admin': user.is_admin,
                'is_active': user.is_active,
                'approval_status': user.approval_status
            }
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

# Her request öncesi IP kontrolü için
@app.before_request
def before_request():
    if current_user.is_authenticated:
        # Kullanıcının IP'si değişmişse güncelle
        if current_user.last_ip != request.remote_addr:
            current_user.last_ip = request.remote_addr
            current_user.last_login = datetime.now(timezone.utc)
            db.session.commit()

@app.route('/api/admin/logs/stats')
@login_required
@admin_required
def get_log_stats():
    try:
        # Toplam log sayısı
        total_logs = SystemLog.query.count()
        
        # Kritik olaylar
        critical_events = SystemLog.query.filter_by(importance='critical').count()
        
        # Bugünkü aktivite
        today = datetime.now().date()
        today_activity = SystemLog.query.filter(
            db.func.date(SystemLog.timestamp) == today
        ).count()
        
        # Olay tipi dağılımı
        event_types = db.session.query(
            SystemLog.event_type,
            db.func.count(SystemLog.id)
        ).group_by(SystemLog.event_type).all()
        
        # Önem seviyesi dağılımı
        importance_levels = db.session.query(
            SystemLog.importance,
            db.func.count(SystemLog.id)
        ).group_by(SystemLog.importance).all()
        
        return jsonify({
            'total_logs': total_logs,
            'critical_events': critical_events,
            'today_activity': today_activity,
            'event_types': dict(event_types),
            'importance_levels': dict(importance_levels)
        })
        
    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 500

@app.route('/api/admin/logs/<int:log_id>/details')
@login_required
@admin_required
def get_log_details(log_id):
    try:
        log = SystemLog.query.get_or_404(log_id)
        user = User.query.get(log.user_id) if log.user_id else None
        
        return jsonify({
            'timestamp': log.timestamp.strftime('%d.%m.%Y %H:%M:%S'),
            'event_type': log.event_type,
            'importance': log.importance,
            'username': user.username if user else 'Sistem',
            'ip_address': log.ip_address,
            'details': log.details,
            'user_agent': log.user_agent if hasattr(log, 'user_agent') else 'Bilinmiyor'
        })
        
    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 500

@app.route('/api/admin/blacklist/export')
@login_required
@admin_required
def export_blacklist():
    format = request.args.get('format', 'csv')
    
    # Kara listedeki kullanıcıları al
    blacklisted_users = User.query.filter(User.blacklist_reason.isnot(None)).all()
    
    if format == 'csv':
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['Kullanıcı Adı', 'Email', 'Telegram', 'Sebep', 'Tarih', 'Ekleyen'])
        
        for user in blacklisted_users:
            writer.writerow([
                user.username,
                user.email,
                user.telegram_username or 'Yok',
                user.blacklist_reason,
                user.blacklisted_at.strftime('%d.%m.%Y %H:%M:%S'),
                User.query.get(user.blacklisted_by_id).username if user.blacklisted_by_id else 'Sistem'
            ])
        
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment;filename=blacklist.csv'}
        )
    
    elif format == 'json':
        blacklist_data = [{
            'username': user.username,
            'email': user.email,
            'telegram': user.telegram_username,
            'reason': user.blacklist_reason,
            'date': user.blacklisted_at.strftime('%d.%m.%Y %H:%M:%S'),
            'added_by': User.query.get(user.blacklisted_by_id).username if user.blacklisted_by_id else 'Sistem'
        } for user in blacklisted_users]
        
        return jsonify(blacklist_data)

# Yönetici paneli için yeni rotalar
@app.route('/admin/users/pending')
@login_required
@admin_required
def admin_pending_users():
    users = User.query.filter_by(approval_status='pending').all()
    return render_template('admin/pending_users.html', users=users)

@app.route('/admin/user/approve/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_approve_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        user.approval_status = 'approved'
        user.approval_date = datetime.now(timezone.utc)
        user.is_active = True  # Hesabı aktifleştir
        
        db.session.commit()
        
        # Onay logunu gönder
        log_message = format_approval_log(user, current_user)
        send_log(log_message, "success")
        
        flash(f'{user.username} kullanıcısı başarıyla onaylandı!', 'success')
        
        # Log kaydı ve Telegram bildirimi
        log_message = f"Kullanıcı Onaylandı:\n👤 Kullanıcı: {user.username}\n👮 Onaylayan: {current_user.username}"
        send_log(log_message, "success")
        
        # Telegram bildirimi gönder
        telegram_link = TelegramLink.query.filter_by(user_id=user.id).first()
        if telegram_link:
            try:
                bot.send_message(
                    chat_id=telegram_link.telegram_id,
                    text=f"""✅ Hesabınız Onaylandı!

Artık sisteme giriş yapabilirsiniz.
🌐 Giriş yapmak için: {request.host_url}login"""
                )
            except Exception as e:
                print(f"Telegram mesaj hatası: {str(e)}")
        
        return redirect(url_for('admin_pending_users'))
        
    except Exception as e:
        db.session.rollback()
        flash(f'Onaylama sırasında bir hata oluştu: {str(e)}', 'error')
        return redirect(url_for('admin_pending_users'))

@app.route('/admin/user/reject/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_reject_user(user_id):
    user = User.query.get_or_404(user_id)
    rejection_reason = request.form.get('rejection_reason')
    user.approval_status = 'rejected'
    user.rejected_at = datetime.now(timezone.utc)
    user.rejected_by_id = current_user.id
    user.rejection_reason = rejection_reason
    user.is_active = False
    db.session.commit()
    flash(f'{user.username} kullanıcısı reddedildi!', 'warning')
    return redirect(url_for('admin_pending_users'))

@app.route('/submit_special_code', methods=['POST'])
@login_required
def submit_special_code():
    try:
        data = request.json
        code = data.get('code')
        
        if not code:
            return jsonify({
                'success': False,
                'message': 'Özel kod gerekli.'
            }), 400
        
        # Özel kodu kontrol et
        special_code = SpecialCode.query.filter_by(code=code).first()
        
        if not special_code or not special_code.is_active:
            return jsonify({
                'success': False,
                'message': 'Geçersiz özel kod.'
            }), 400
            
        # Kullanım limitini kontrol et
        if special_code.max_uses and special_code.current_uses >= special_code.max_uses:
            return jsonify({
                'success': False,
                'message': 'Bu kod maksimum kullanım limitine ulaştı.'
            }), 400
            
        # Süre kontrolü
        if special_code.expires_at and special_code.expires_at < datetime.now(timezone.utc):
            return jsonify({
                'success': False,
                'message': 'Bu kodun süresi dolmuş.'
            }), 400
        
        # Hediye kodu oluştur
        gift_code = GiftCode(
            code=''.join(random.choices(string.ascii_uppercase + string.digits, k=8)),
            type='special',
            category='hediye_kodu',
            max_uses=1,
            amount=special_code.amount,
            expires_at=datetime.now(timezone.utc) + timedelta(days=1),
            created_by_id=current_user.id,
            special_code_id=special_code.id,
            is_active=True
        )
        
        # Özel kod kullanımını artır
        special_code.current_uses += 1
        
        # Kullanım logunu kaydet
        log = CodeUsageLog(
            user_id=current_user.id,
            code=special_code.code,
            category='special_code',
            status='success',
            details=f'Hediye kodu oluşturuldu: {gift_code.code}'
        )
        
        db.session.add(gift_code)
        db.session.add(log)
        db.session.commit()
        
        # Özel kod kullanım logunu gönder
        log_message = format_special_code_log(current_user, special_code, gift_code)
        send_log(log_message, "info")
        
        # Telegram bildirimi gönder
        if current_user.telegram_id:
            try:
                bot.send_message(
                    chat_id=current_user.telegram_id,
                    text=f"""🎉 Hediye Kodunuz Hazır!

🎮 Kod: {gift_code.code}
💰 Miktar: {gift_code.amount}
⏰ Son Kullanım: {gift_code.expires_at.strftime('%d.%m.%Y %H:%M')}

⚠️ Bu kod 24 saat geçerlidir ve tek kullanımlıktır."""
                )
            except Exception as e:
                print(f"Telegram mesaj hatası: {str(e)}")
        
        return jsonify({
            'success': True,
            'message': 'Hediye kodunuz başarıyla oluşturuldu!',
            'gift_code': gift_code.code
        })
        
    except Exception as e:
        print(f"Özel kod hatası: {str(e)}")
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': 'Bir hata oluştu. Lütfen daha sonra tekrar deneyin.'
        }), 500

# Kayıt işlemi için log formatı
def format_registration_log(user):
    return f"""📝 Yeni Kullanıcı Kaydı

👤 Kullanıcı Bilgileri:
├ Kullanıcı Adı: {user.username}
├ Email: {user.email}
├ Betgit ID: {user.betgit_id}
├ Hasbet ID: {user.hasbet_id}
├ Kayıt IP: {user.registration_ip}
└ Kayıt Tarihi: {user.registration_date.strftime('%d.%m.%Y %H:%M')}"""

# Telegram bağlantısı için log formatı
def format_telegram_link_log(user, telegram_link):
    return f"""📱 Yeni Telegram Bağlantısı

👤 Kullanıcı Bilgileri:
├ Kullanıcı Adı: {user.username}
├ Betgit ID: {user.betgit_id}
├ Hasbet ID: {user.hasbet_id}
├ Kayıt IP: {user.registration_ip}
└ Kayıt Tarihi: {user.registration_date.strftime('%d.%m.%Y %H:%M')}

📞 Telegram Bilgileri:
├ Telegram ID: {telegram_link.telegram_id}
└ Telegram Kullanıcı Adı: @{telegram_link.telegram_username}"""

# Özel kod kullanımı için log formatı
def format_special_code_log(user, special_code, gift_code):
    return f"""🎟️ Özel Kod Kullanıldı

👤 Kullanıcı Bilgileri:
├ Kullanıcı Adı: {user.username}
├ Telegram: @{user.telegram_username or 'Bağlı Değil'}
└ Kullanım Tarihi: {datetime.now(timezone.utc).strftime('%d.%m.%Y %H:%M')}

🎮 Kod Detayları:
├ Özel Kod: {special_code.code}
├ Hediye Kodu: {gift_code.code}
├ Miktar: {gift_code.amount}
└ Son Kullanım: {gift_code.expires_at.strftime('%d.%m.%Y %H:%M')}"""

# Kullanıcı onayı için log formatı
def format_approval_log(user, admin):
    return f"""✅ Kullanıcı Onaylandı

👤 Kullanıcı Bilgileri:
├ Kullanıcı Adı: {user.username}
├ Email: {user.email}
├ Betgit ID: {user.betgit_id}
└ Hasbet ID: {user.hasbet_id}

👮 Onay Bilgileri:
├ Onaylayan: {admin.username}
├ Onay Tarihi: {datetime.now(timezone.utc).strftime('%d.%m.%Y %H:%M')}
└ Durum: Aktif"""

# Log kanalına mesaj gönderme fonksiyonu
def send_log(message, alert_type="info"):
    try:
        # Emoji ve renk seçimi
        emoji_map = {
            "info": "ℹ️",
            "success": "✅",
            "warning": "⚠️",
            "error": "❌",
            "critical": "🚨"
        }
        emoji = emoji_map.get(alert_type, "ℹ️")
        
        # Zaman damgası
        timestamp = datetime.now(timezone.utc).strftime("%d.%m.%Y %H:%M:%S")
        
        # Log mesajını formatla
        log_message = f"""{emoji} LOG MESAJI
⏰ Zaman: {timestamp}
📝 Detay: {message}"""
        
        # Log kanalına gönder
        bot.send_message(
            chat_id=config.LOG_CHANNEL_ID,
            text=log_message
        )
    except Exception as e:
        print(f"Log mesajı gönderilemedi: {str(e)}")

# Hata durumlarında da log gönder
@app.errorhandler(Exception)
def handle_error(error):
    log_message = f"""❌ HATA OLUŞTU:
🔴 Hata: {str(error)}
👤 Kullanıcı: {current_user.username if not current_user.is_anonymous else 'Anonim'}
🌐 IP: {request.remote_addr}
🔗 URL: {request.url}"""
    send_log(log_message, "error")
    return "Bir hata oluştu", 500

@app.route('/admin/analytics')
@login_required
@admin_required
def admin_analytics():
    # Son 24 saatteki istatistikler
    now = datetime.now(timezone.utc)
    yesterday = now - timedelta(days=1)
    last_hour = now - timedelta(hours=1)
    
    # Toplam kullanıcı sayısı ve artış oranı
    total_users = User.query.count()
    new_users = User.query.filter(User.registration_date > yesterday).count()
    user_increase = round((new_users / total_users) * 100, 1) if total_users > 0 else 0
    
    # Aktif kodlar ve kullanım oranı
    total_codes = GiftCode.query.filter_by(is_active=True).count()
    used_codes = GiftCode.query.filter(
        GiftCode.is_active == True,
        GiftCode.current_uses > 0
    ).count()
    code_usage = round((used_codes / total_codes) * 100, 1) if total_codes > 0 else 0
    
    # Telegram bağlantıları
    telegram_users = User.query.filter_by(telegram_verified=True).count()
    new_telegram = User.query.filter(
        User.telegram_verified == True,
        User.telegram_id != None,
        User.registration_date > yesterday
    ).count()
    telegram_increase = round((new_telegram / telegram_users) * 100, 1) if telegram_users > 0 else 0
    
    # Aktif kullanıcılar
    active_users = User.query.filter(User.last_login > last_hour).count()
    prev_hour_users = User.query.filter(
        User.last_login > (last_hour - timedelta(hours=1)),
        User.last_login <= last_hour
    ).count()
    active_decrease = round(((prev_hour_users - active_users) / prev_hour_users) * 100, 1) if prev_hour_users > 0 else 0
    
    # Kullanım grafiği için veriler
    usage_data = []
    usage_labels = []
    for i in range(24):
        time = now - timedelta(hours=i)
        count = CodeUsageLog.query.filter(
            CodeUsageLog.timestamp > time - timedelta(hours=1),
            CodeUsageLog.timestamp <= time
        ).count()
        usage_data.insert(0, count)
        usage_labels.insert(0, time.strftime('%H:00'))
    
    # Platform dağılımı
    platform_data = [
        GiftCode.query.filter_by(category='betgit').count(),
        GiftCode.query.filter_by(category='hasbet').count(),
        GiftCode.query.filter_by(category='other').count()
    ]
    
    # Son aktiviteler
    activities = []
    logs = CodeUsageLog.query.order_by(CodeUsageLog.timestamp.desc()).limit(50).all()
    for log in logs:
        user = User.query.get(log.user_id)
        activities.append({
            'timestamp': log.timestamp,
            'username': user.username if user else 'Silinmiş Kullanıcı',
            'action': 'Kod Kullanımı',
            'platform': log.category,
            'code': log.code,
            'status': log.status,
            'status_color': 'success' if log.status == 'success' else 'danger'
        })
    
    return render_template('admin/analytics.html',
                         total_users=total_users,
                         user_increase=user_increase,
                         total_codes=total_codes,
                         code_usage=code_usage,
                         telegram_users=telegram_users,
                         telegram_increase=telegram_increase,
                         active_users=active_users,
                         active_decrease=active_decrease,
                         usage_data=usage_data,
                         usage_labels=usage_labels,
                         platform_data=platform_data,
                         activities=activities)

@app.route('/api/admin/analytics/usage/<period>')
@login_required
@admin_required
def get_usage_data(period):
    now = datetime.now(timezone.utc)
    data = []
    labels = []
    
    if period == 'daily':
        for i in range(24):
            time = now - timedelta(hours=i)
            count = CodeUsageLog.query.filter(
                CodeUsageLog.timestamp > time - timedelta(hours=1),
                CodeUsageLog.timestamp <= time
            ).count()
            data.insert(0, count)
            labels.insert(0, time.strftime('%H:00'))
    
    elif period == 'weekly':
        for i in range(7):
            date = now - timedelta(days=i)
            count = CodeUsageLog.query.filter(
                CodeUsageLog.timestamp > date - timedelta(days=1),
                CodeUsageLog.timestamp <= date
            ).count()
            data.insert(0, count)
            labels.insert(0, date.strftime('%d.%m'))
    
    elif period == 'monthly':
        for i in range(30):
            date = now - timedelta(days=i)
            count = CodeUsageLog.query.filter(
                CodeUsageLog.timestamp > date - timedelta(days=1),
                CodeUsageLog.timestamp <= date
            ).count()
            data.insert(0, count)
            labels.insert(0, date.strftime('%d.%m'))
    
    return jsonify({
        'data': data,
        'labels': labels
    })

@app.route('/api/admin/analytics/stats')
@login_required
@admin_required
def get_current_stats():
    now = datetime.now(timezone.utc)
    
    # Anlık istatistikleri hesapla
    stats = {
        'total_users': {
            'value': User.query.count(),
            'change': calculate_change(User, 'registration_date')
        },
        'active_codes': {
            'value': GiftCode.query.filter_by(is_active=True).count(),
            'change': calculate_code_usage()
        },
        'telegram_users': {
            'value': User.query.filter_by(telegram_verified=True).count(),
            'change': calculate_change(User, 'telegram_verified')
        },
        'active_users': {
            'value': User.query.filter(User.last_login > now - timedelta(hours=1)).count(),
            'change': calculate_active_users_change()
        }
    }
    
    return jsonify(stats)

def calculate_change(model, field, hours=24):
    now = datetime.now(timezone.utc)
    current = model.query.filter(getattr(model, field) > now - timedelta(hours=hours)).count()
    previous = model.query.filter(
        getattr(model, field) > now - timedelta(hours=hours*2),
        getattr(model, field) <= now - timedelta(hours=hours)
    ).count()
    
    return round(((current - previous) / previous) * 100, 1) if previous > 0 else 0

def calculate_code_usage():
    total = GiftCode.query.filter_by(is_active=True).count()
    used = GiftCode.query.filter(
        GiftCode.is_active == True,
        GiftCode.current_uses > 0
    ).count()
    
    return round((used / total) * 100, 1) if total > 0 else 0

def calculate_active_users_change():
    now = datetime.now(timezone.utc)
    current = User.query.filter(User.last_login > now - timedelta(hours=1)).count()
    previous = User.query.filter(
        User.last_login > now - timedelta(hours=2),
        User.last_login <= now - timedelta(hours=1)
    ).count()
    
    return round(((current - previous) / previous) * 100, 1) if previous > 0 else 0

# Hediye Kodu Oluşturma API'si
@app.route('/api/admin/gift_codes/create', methods=['POST'])
@login_required
@admin_required
def create_gift_code():
    try:
        data = request.get_json()
        code = data.get('code')
        max_uses = data.get('max_uses', 1)
        expires_at = datetime.strptime(data.get('expires_at'), '%Y-%m-%dT%H:%M')  # datetime-local format
        category = data.get('category')
        
        new_code = GiftCode(
            code=code,
            max_uses=max_uses,
            expires_at=expires_at,
            category=category,
            created_by_id=current_user.id,
            is_active=True,
            current_uses=0
        )
        
        db.session.add(new_code)
        db.session.commit()
        
        # Log kaydı
        log = SystemLog(
            event_type='admin',
            user_id=current_user.id,
            message='Hediye Kodu Oluşturuldu',
            details=f'Kod: {code}, Platform: {category}',
            importance='medium',
            status='success'
        )
        db.session.add(log)
        db.session.commit()
        
        return jsonify({"success": True, "message": "Hediye kodu başarıyla oluşturuldu"})
    except Exception as e:
        print(f"Hediye kodu oluşturma hatası: {str(e)}")  # Debug log
        return jsonify({"success": False, "message": str(e)})

# Özel Kod Oluşturma API'si
@app.route('/api/admin/special_codes/create', methods=['POST'])
@login_required
@admin_required
def create_special_code():
    try:
        data = request.get_json()
        code = data.get('code')
        max_uses = data.get('max_uses', 1)
        expires_at = datetime.strptime(data.get('expires_at'), '%Y-%m-%dT%H:%M')  # datetime-local format
        notes = data.get('notes', '')
        
        new_code = SpecialCode(
            code=code,
            max_uses=max_uses,
            expires_at=expires_at,
            notes=notes,
            created_by_id=current_user.id,
            is_active=True,
            current_uses=0
        )
        
        db.session.add(new_code)
        db.session.commit()
        
        # Log kaydı
        log = SystemLog(
            event_type='admin',
            user_id=current_user.id,
            message='Özel Kod Oluşturuldu',
            details=f'Kod: {code}',
            importance='medium',
            status='success'
        )
        db.session.add(log)
        db.session.commit()
        
        return jsonify({"success": True, "message": "Özel kod başarıyla oluşturuldu"})
    except Exception as e:
        print(f"Özel kod oluşturma hatası: {str(e)}")  # Debug log
        return jsonify({"success": False, "message": str(e)})

if __name__ == '__main__':
    app.run(debug=True, port=5000) 