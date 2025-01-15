from datetime import datetime, timezone
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from extensions import db
from sqlalchemy import event

# User-Gift Codes ilişki tablosu
user_gift_codes = db.Table('user_gift_codes',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('gift_code_id', db.Integer, db.ForeignKey('gift_code.id'), primary_key=True)
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    betgit_id = db.Column(db.String(80), nullable=False)
    hasbet_id = db.Column(db.String(80), nullable=False)
    telegram_id = db.Column(db.String(32), unique=True, nullable=True)
    special_code = db.Column(db.String(80), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    is_vip = db.Column(db.Boolean, default=False)
    
    # Onay bilgileri
    approval_status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    approval_date = db.Column(db.DateTime(timezone=True))
    rejected_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    rejected_at = db.Column(db.DateTime(timezone=True))
    rejection_reason = db.Column(db.Text)
    
    # Kara liste bilgileri
    blacklist_reason = db.Column(db.Text)
    blacklisted_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    blacklisted_at = db.Column(db.DateTime(timezone=True))
    
    # IP ve konum bilgileri
    registration_ip = db.Column(db.String(45))  # IPv6 için 45 karakter
    last_ip = db.Column(db.String(45))
    last_login = db.Column(db.DateTime(timezone=True))
    registration_date = db.Column(db.DateTime(timezone=True), default=datetime.now(timezone.utc))
    
    # Platform ID'leri
    betgit_id = db.Column(db.String(50), unique=True)
    hasbet_id = db.Column(db.String(50), unique=True)
    
    # Telegram bilgileri
    telegram_username = db.Column(db.String(32), nullable=True)
    telegram_verified = db.Column(db.Boolean, default=False)
    
    # İlişkiler
    gift_codes = db.relationship('GiftCode', secondary=user_gift_codes, lazy='dynamic',
                                backref=db.backref('users', lazy=True))
    
    # Şifre işlemleri
    def set_password(self, password):
        self.password = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password, password)
    
    @property
    def is_blacklisted(self):
        """Kullanıcının kara listede olup olmadığını kontrol et"""
        return self.blacklist_reason is not None
    
    def __repr__(self):
        return f'<User {self.username}>'

class GiftCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50), unique=True, nullable=False)
    category = db.Column(db.String(50))
    max_uses = db.Column(db.Integer, default=1)
    current_uses = db.Column(db.Integer, default=0)
    amount = db.Column(db.Float)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    special_code_id = db.Column(db.Integer, db.ForeignKey('special_code.id'))
    notes = db.Column(db.Text)
    is_hidden = db.Column(db.Boolean, default=False)

class SpecialCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50), unique=True, nullable=False)
    category = db.Column(db.String(50))
    max_uses = db.Column(db.Integer)
    current_uses = db.Column(db.Integer, default=0)
    amount = db.Column(db.Float)  # Hediye kodu miktarı
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    notes = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)  # Aktif/Pasif durumu
    gift_codes = db.relationship('GiftCode', backref='special_code')

class CodeUsageLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    code = db.Column(db.String(50))
    category = db.Column(db.String(50))
    status = db.Column(db.String(20))  # success, failed
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.Text)

class TelegramLink(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    telegram_id = db.Column(db.String(32), unique=True, nullable=False)
    telegram_username = db.Column(db.String(32))
    verification_code = db.Column(db.String(6))
    is_verified = db.Column(db.Boolean, default=False)
    verified_at = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class SystemLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime(timezone=True), default=datetime.now(timezone.utc))
    event_type = db.Column(db.String(50))  # login, register, code_use, blacklist, etc.
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    ip_address = db.Column(db.String(45))
    message = db.Column(db.Text)
    details = db.Column(db.Text)
    importance = db.Column(db.String(20))  # low, medium, high, critical
    status = db.Column(db.String(20))  # success, warning, error
    
    # User ilişkisini ekle
    user = db.relationship('User', backref=db.backref('logs', lazy=True)) 

@event.listens_for(TelegramLink.telegram_username, 'set')
def telegram_username_change_handler(target, value, oldvalue, initiator):
    if oldvalue and value != oldvalue:
        # Log kaydı
        log = SystemLog(
            event_type='telegram',
            user_id=target.user_id,
            message=f'Telegram kullanıcı adı değiştirildi',
            details=f'Eski: @{oldvalue} -> Yeni: @{value}',
            importance='medium',
            status='info'
        )
        db.session.add(log) 