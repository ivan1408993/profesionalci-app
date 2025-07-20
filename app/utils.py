import hashlib
from flask import current_app
from itsdangerous import URLSafeTimedSerializer
from . import db
from .models import DriverCard
import os

# ✅ Heširanje JMBG-a sa salt-om iz konfiguracije
def hash_jmbg(jmbg):
    salt = current_app.config.get('JMBG_SALT', '')
    return hashlib.sha256((jmbg + salt).encode('utf-8')).hexdigest()

def generate_salt(length=16):
    return os.urandom(length)  # vraća bytes

def hash_jmbg_with_salt(jmbg, salt: bytes) -> str:
    # Heširaj jmbg (string) + salt (bytes)
    hasher = hashlib.sha256()
    hasher.update(jmbg.encode('utf-8'))
    hasher.update(salt)
    return hasher.hexdigest()

# ✅ Generisanje reset token-a za oporavak lozinke
def generate_reset_token(email):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='password-reset-salt')

# ✅ Verifikacija reset token-a
def verify_reset_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=expiration)
    except Exception:
        return None
    return email

# ✅ Dodavanje nove tahograf kartice i deaktivacija starih
def add_new_driver_card(driver, new_card_number, issue_date=None, expiry_date=None):
    for card in driver.cards:
        card.is_active = False  # Deaktiviraj sve postojeće kartice

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
