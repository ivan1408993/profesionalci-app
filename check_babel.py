from flask import Flask
from flask_babel import Babel, _

app = Flask(__name__)
app.config['BABEL_TRANSLATION_DIRECTORIES'] = "/opt/render/project/src/app/translations"  # apsolutna putanja
babel = Babel(app)

with app.app_context():
    babel.locale_selector_func = lambda: 'sr'
    print("SR:", _("Dobrodošli"))

    babel.locale_selector_func = lambda: 'en'
    print("EN:", _("Dobrodošli"))

    babel.locale_selector_func = lambda: 'de'
    print("DE:", _("Dobrodošli"))