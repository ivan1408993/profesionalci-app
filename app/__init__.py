from flask import Flask, session, request, g, redirect  # dodali redirect
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
    # 1. cookie lang
    if request.cookies.get('lang'):
        return request.cookies.get('lang')
    # 2. browser accept-languages
    return request.accept_languages.best_match(['sr', 'en', 'de']) or 'sr'


def create_app():
    app = Flask(__name__)

    # === BAZA ===
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = 'tajna123'
    app.config['JMBG_SALT'] = 'moj_sakriveni_salt_2025'

    # === JEZIK (Babel) ===
    app.config['BABEL_DEFAULT_LOCALE'] = 'sr'
    app_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    app.config['BABEL_TRANSLATION_DIRECTORIES'] = os.path.join(app_root, 'translations')

    # === EMAIL ===
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = ('Profesionalci', os.environ.get('MAIL_USERNAME'))

    # === SESIJE ===
   # SESIJE (mora pre Session(app))
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['SESSION_PERMANENT'] = True
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
    app.config['SESSION_FILE_DIR'] = '/tmp/flask_session'
    os.makedirs(app.config['SESSION_FILE_DIR'], exist_ok=True)

    # važna podešavanja cookie-ja — primenjuju se na sve poddomene
    app.config['SESSION_COOKIE_NAME'] = os.environ.get('SESSION_COOKIE_NAME', 'session')
    app.config['SESSION_COOKIE_DOMAIN'] = '.driverrate.com'   # VAŽNO: odnosi se na www + bez-www
    app.config['SESSION_COOKIE_PATH'] = '/'
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    # Inicijalizacija Flask-Session
    Session(app)

    # === EKSTENZIJE ===
    db.init_app(app)
    migrate.init_app(app, db)
    babel.init_app(app, locale_selector=get_locale)
    mail.init_app(app)

    # === LOKALIZACIJA ===
    @app.before_request
    def set_current_lang():
        g.current_lang = get_locale()

    # 🟢 Dodato: redirect sa Render domena na pravi domen
    @app.before_request
    def redirect_to_custom_domain():
        if request.host.startswith("profesionalci.onrender.com"):
            target_url = request.url.replace("profesionalci.onrender.com", "www.driverrate.com")
            return redirect(target_url, code=301)

    # === RUTE ===
    from .routes import main
    app.register_blueprint(main)

    return app
