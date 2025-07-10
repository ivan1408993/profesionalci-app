import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'tajna_za_flask_aplikaciju'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///app.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Додатни конфигурациони параметар за хеширање JMBG-а
    JMBG_SALT = os.environ.get('JMBG_SALT') or 'moj_sakriveni_salt_2025'
