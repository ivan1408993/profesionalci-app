from flask import Flask, session, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_babel import Babel
from flask_mail import Mail  # ➕ Додато
from .helpers import konvertuj_tekst
import os

db = SQLAlchemy()
migrate = Migrate()
babel = Babel()
mail = Mail()  # ➕ Додато

def create_app():
    app = Flask(__name__)

    # ➕ Конфигурација
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = 'tajna123'
    app.config['JMBG_SALT'] = 'moj_sakriveni_salt_2025'
    app.config['BABEL_DEFAULT_LOCALE'] = 'sr'

    # ➕ Flask-Mail конфигурација (пример за Gmail SMTP)
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')  # Пример: 'tvoja.adresa@gmail.com'
    app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')  # Пример: App password
    app.config['MAIL_DEFAULT_SENDER'] = ('Професионалци', os.environ.get('MAIL_USERNAME'))

    # ➕ Иницијализација
    db.init_app(app)
    migrate.init_app(app, db)
    babel.init_app(app)
    mail.init_app(app)  # ➕ Додато

    # Локализација
    def get_locale():
        return session.get('lang') or request.accept_languages.best_match(['sr', 'en', 'de']) or 'sr'

    babel.locale_selector_func = get_locale

    # Регистрација рута
    from .routes import main
    app.register_blueprint(main)

    return app
