import os
from dotenv import load_dotenv

# ➕ Učitavanje .env fajla pre kreiranja aplikacije
load_dotenv()
from app import create_app, db


app = create_app()

with app.app_context():
    db.create_all()