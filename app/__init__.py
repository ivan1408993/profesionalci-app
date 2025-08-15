from flask import Flask, session, request, g  # dodaj g ovde
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_babel import Babel
from flask_mail import Mail
from .helpers import konvertuj_tekst
import os
from dotenv import load_dotenv
from flask_session import Session
from datetime import timedelta

load_dotenv()

db = SQLAlchemy()
migrate = Migrate()
babel = Babel()
mail = Mail()

def get_locale():
    # Redosled prioriteta:
    # 1. jezik iz session-a
    # 2. najbolji jezik iz browser-a
    # 3. fallback na sr
    lang = session.get('lang')
    print("CURRENT SESSION LANG:", lang)  # debug ispis
    return lang or request.accept_languages.best_match(['sr', 'en', 'de']) or 'sr'


def create_app():
    app = Flask(__name__)

    # Baza
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = 'tajna123'
    app.config['JMBG_SALT'] = 'moj_sakriveni_salt_2025'

    # Babel podešavanja
    app.config['BABEL_DEFAULT_LOCALE'] = 'sr'
    app_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    app.config['BABEL_TRANSLATION_DIRECTORIES'] = os.path.join(app_root, 'translations')


    # Email podešavanja
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = ('Profesionalci', os.environ.get('MAIL_USERNAME'))

      # Konfiguriši session da se čuva u fajlovima (može i Redis, baza...)
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['SESSION_PERMANENT'] = True
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
    app.config['SESSION_FILE_DIR'] = os.path.join(app.instance_path, 'flask_session')
    os.makedirs(app.config['SESSION_FILE_DIR'], exist_ok=True)


    # Inicijalizuj Flask-Session
    Session(app)


    # Inicijalizacija ekstenzija
    db.init_app(app)
    migrate.init_app(app, db)
    babel.init_app(app, locale_selector=get_locale)
    mail.init_app(app)

    # Ovo dodajemo da g.current_lang radi svuda
    @app.before_request
    def set_current_lang():
        g.current_lang = get_locale()

    # Registracija ruta
    from .routes import main
    app.register_blueprint(main)

    return app
