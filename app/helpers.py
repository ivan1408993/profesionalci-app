import cyrtranslit

def konvertuj_tekst(tekst: str, target_script: str) -> str:
    if not tekst:
        return ''
    if target_script == 'latin':
        return cyrtranslit.to_latin(tekst)
    elif target_script == 'cyrillic':
        return cyrtranslit.to_cyrillic(tekst)
    else:
        return tekst
