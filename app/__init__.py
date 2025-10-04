from flask import Flask, session, request, g, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_babel import Babel
from flask_mail import Mail
from flask_session import Session
from datetime import timedelta
from dotenv import load_dotenv
import os

from .helpers import konvertuj_tekst

load_dotenv()

db = SQLAlchemy()
migrate = Migrate()
babel = Babel()
mail = Mail()


def get_locale():
    # 1️⃣ cookie lang
    if request.cookies.get('lang'):
        return request.cookies.get('lang')
    # 2️⃣ browser accept-languages
    return request.accept_languages.best_match(['sr', 'en', 'de']) or 'sr'


def create_app():
    app = Flask(__name__)

    # === BAZA ===
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'tajna123')
    app.config['JMBG_SALT'] = 'moj_sakriveni_salt_2025'

    # === BABEL (prevodi) ===
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

    # === SESSION podešavanja ===
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['SESSION_PERMANENT'] = True
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
    app.config['SESSION_FILE_DIR'] = os.path.join(app.instance_path, 'flask_session')
    os.makedirs(app.config['SESSION_FILE_DIR'], exist_ok=True)

    # ⚙️ Cookie konfiguracija — stabilna za Render + Cloudflare
    if "driverrate.com" in request.host:
        cookie_domain = ".driverrate.com"
    else:
        cookie_domain = None  # Render ili lokalno

    app.config.update(
        SESSION_COOKIE_DOMAIN=cookie_domain,
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_HTTPONLY=True
    )

    # === Inicijalizacija ekstenzija ===
    Session(app)
    db.init_app(app)
    migrate.init_app(app, db)
    babel.init_app(app, locale_selector=get_locale)
    mail.init_app(app)

    # === Pre svakog zahteva ===
    @app.before_request
    def before_every_request():
        # 1️⃣ Ako nije HTTPS, redirektuj na HTTPS
        if not request.is_secure and not app.debug and request.headers.get('X-Forwarded-Proto', 'http') != 'https':
            url = request.url.replace("http://", "https://", 1)
            return redirect(url, code=301)

        # 2️⃣ Ako nema www, redirektuj na www.driverrate.com
        host = request.host.lower()
        if host == "driverrate.com":
            new_url = request.url.replace("://driverrate.com", "://www.driverrate.com")
            return redirect(new_url, code=301)

        # 3️⃣ Postavi trenutni jezik
        g.current_lang = get_locale()

    # === Registracija ruta ===
    from .routes import main
    app.register_blueprint(main)

    return app
