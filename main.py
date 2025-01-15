import os
import asyncio
from app import app
from bot import create_application, setup_bot_handlers
import config as app_config
import nest_asyncio
from hypercorn.config import Config as HyperConfig
from hypercorn.asyncio import serve

# Event loop çakışmalarını önle
nest_asyncio.apply()

async def run_bot(bot_app):
    """Bot'u çalıştır"""
    try:
        await bot_app.initialize()
        await bot_app.start()
        print("Bot başarıyla başlatıldı!")
        
        # Polling'i başlat
        await bot_app.updater.start_polling(drop_pending_updates=True)
        
        # Bot çalışır durumda kalması için bekle
        while True:
            await asyncio.sleep(1)
            
    except Exception as e:
        print(f"Bot hatası: {e}")
    finally:
        await bot_app.stop()

async def run_web():
    """Web sunucusunu çalıştır"""
    hyper_config = HyperConfig()
    hyper_config.bind = [f"{app_config.HOST}:{app_config.PORT}"]
    hyper_config.use_reloader = False
    
    print(f"Web sunucusu başlatılıyor... ({app_config.HOST}:{app_config.PORT})")
    await serve(app, hyper_config)

async def main():
    print("Uygulama başlatılıyor...")
    print("\n=== Başlatılıyor ===")
    
    try:
        # Bot uygulamasını başlat
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Flask uygulama bağlamını oluştur
        app_context = app.app_context()
        app_context.push()
        
        bot_app = loop.run_until_complete(create_application())
        print("🤖 Bot başlatılıyor...")
        
        # Bot handler'larını ekle
        setup_bot_handlers(bot_app)
        print("🤖 Bot handler'ları eklendi!")

        # Bot ve web sunucusunu birlikte çalıştır
        await asyncio.gather(
            run_bot(bot_app),
            run_web()
        )
        
    except Exception as e:
        print(f"Hata: {str(e)}")
        raise
    finally:
        try:
            app_context.pop()
            loop.close()
        except:
            pass

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nUygulama kapatılıyor...")
    except Exception as e:
        print(f"Kritik hata: {e}")