from functools import wraps
from flask import session, redirect, url_for, flash, g
from flask_babel import _

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Provera da li je korisnik prijavljen
        if 'user_id' not in session or not session['user_id']:
            flash(_("Morate biti prijavljeni da biste pristupili ovoj stranici."), "warning")
            return redirect(url_for('main.login'))
        return f(*args, **kwargs)
    return decorated_function

def superadmin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Provera da li je korisnik superadmin
        if session.get('user_type') != 'superadmin':
            flash(_("Nemate pristup ovoj stranici."), "danger")
            # Opcionalno može redirect na dashboard ako je prijavljen
            if session.get('user_type') == 'employer':
                return redirect(url_for('main.drivers'))
            return redirect(url_for('main.login'))
        return f(*args, **kwargs)
    return decorated_function
