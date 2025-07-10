# app/utils/translator.py

import cyrtranslit
from googletrans import Translator

translator = Translator()

def konvertuj_pismo(text, to_script='cir'):
    if to_script == 'lat':
        return cyrtranslit.to_latin(text)
    elif to_script == 'cir':
        return cyrtranslit.to_cyrillic(text)
    return text

def prevod_teksta(text, lang='en'):
    try:
        translated = translator.translate(text, src='sr', dest=lang)
        return translated.text
    except Exception:
        return text  # ako padne prevod, vrati original
