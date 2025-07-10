import os
from app import db, create_app
from app.models import *

app = create_app()

with app.app_context():
    db.drop_all()
    db.session.commit()

if os.path.exists("app.db"):
    os.remove("app.db")
    print("🗑️ Baza obrisana.")

# Поново иницијализуј апликацију (да би направио нову празну базу)
app = create_app()

with app.app_context():
    db.create_all()
    print("✅ Baza resetovana i tabele su kreirane.")
