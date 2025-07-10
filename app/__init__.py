from flask import Flask, session, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_babel import Babel
from .helpers import konvertuj_tekst


db = SQLAlchemy()
migrate = Migrate()
babel = Babel()

def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:lozinka123@localhost/profesionalci_db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = 'tajna123'
    app.config['JMBG_SALT'] = 'moj_sakriveni_salt_2025'  # ✅ Додато ово
    app.config['BABEL_DEFAULT_LOCALE'] = 'sr'

    db.init_app(app)
    migrate.init_app(app, db)
    babel.init_app(app)

    def get_locale():
        return session.get('lang') or request.accept_languages.best_match(['sr', 'en', 'de']) or 'sr'

    babel.locale_selector_func = get_locale

    from .routes import main
    app.register_blueprint(main)

    return app

