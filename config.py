import os
import logging
import secrets
from dotenv import load_dotenv

# .env dosyasını yükle
load_dotenv()

# Bot token'ı - .env'deki BOT_TOKEN değişkenini kullan
BOT_TOKEN = os.getenv('BOT_TOKEN')
BOT_USERNAME = "foolingaround_bot"  # Telegram bot kullanıcı adı

# Telegram ID'leri
GROUP_ID = int(os.getenv('GROUP_ID', -1002256325762))
LOG_CHANNEL_ID = int(os.getenv('LOG_CHANNEL_ID', -1002413200248))
ADMIN_ID = int(os.getenv('ADMIN_ID', 7344818960))

# Admin ayarları
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'becool')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'muharrem')

# Flask ayarları
DEBUG = os.getenv('FLASK_DEBUG', 'True').lower() == 'true'
HOST = os.getenv('FLASK_HOST', '0.0.0.0')
PORT = int(os.getenv('FLASK_PORT', 5000))
SECRET_KEY = os.getenv('SECRET_KEY', secrets.token_hex(32))

# Database ayarları
DATABASE_URI = os.getenv('DATABASE_URI', 'sqlite:///instance/database.db')
SQLALCHEMY_TRACK_MODIFICATIONS = False

# Platform linkleri
PLATFORM_LINKS = {
    'betgit': 'https://bit.ly/betgitsabriabi',
    'hasbet': 'https://bit.ly/3KkcLSv',
    'telegram': 'https://t.me/foolingaround_bot'  # Bot linki
}

# Telegram grup linki
TELEGRAM_GROUP_LINK = "https://t.me/foolingaround"  # Grubun linki

# Logger ayarları
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_LEVEL = logging.INFO

# Bot logger'ı oluştur
bot_logger = logging.getLogger('bot')
bot_logger.setLevel(LOG_LEVEL)

# Log dosyası için handler
if not os.path.exists('logs'):
    os.makedirs('logs')
    
file_handler = logging.FileHandler('logs/bot.log')
file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
bot_logger.addHandler(file_handler)

# Konsol için handler
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter(LOG_FORMAT))
bot_logger.addHandler(console_handler)

def setup_logger(logger_name):
    """Logger ayarlarını yapılandır"""
    # Logger'ı oluştur
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.INFO)
    
    # Logs klasörünü oluştur
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    # Handler'ları oluştur
    file_handler = logging.FileHandler(f'logs/{logger_name}.log')
    console_handler = logging.StreamHandler()
    
    # Formatter oluştur
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    # Handler'ları logger'a ekle
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger 