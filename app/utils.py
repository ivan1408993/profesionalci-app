import hashlib
from flask import current_app
from itsdangerous import URLSafeTimedSerializer
from . import db
from .models import DriverCard
import os

# ✅ Хеширање JMBG-а са salt-ом из конфигурације
def hash_jmbg(jmbg):
    salt = current_app.config.get('JMBG_SALT', '')
    return hashlib.sha256((jmbg + salt).encode('utf-8')).hexdigest()

def generate_salt(length=16):
    return os.urandom(length)  # враћа bytes

def hash_jmbg_with_salt(jmbg, salt: bytes) -> str:
    # Хеширај jmbg (string) + salt (bytes)
    hasher = hashlib.sha256()
    hasher.update(jmbg.encode('utf-8'))
    hasher.update(salt)
    return hasher.hexdigest()

# ✅ Генерисање reset token-а за опоравак лозинке
def generate_reset_token(email):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='password-reset-salt')

# ✅ Верификација reset token-а
def verify_reset_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=expiration)
    except Exception:
        return None
    return email

# ✅ Додавање нове тахограф картице и деактивација старих
def add_new_driver_card(driver, new_card_number, issue_date=None, expiry_date=None):
    for card in driver.cards:
        card.is_active = False  # Деактивирај све постојеће картице

    new_card = DriverCard(
        card_number=new_card_number,
        driver_id=driver.id,
        is_active=True,
        issue_date=issue_date,
        expiry_date=expiry_date
    )

    db.session.add(new_card)
    db.session.commit()
    return new_card
