from functools import wraps
from flask import session, redirect, url_for, flash

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Морате бити пријављени да бисте приступили овој страници.")
            return redirect(url_for('main.login'))
        return f(*args, **kwargs)
    return decorated_function

def superadmin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('user_type') != 'superadmin':
            flash("Немате приступ овој страници.")
            return redirect(url_for('main.login'))
        return f(*args, **kwargs)
    return decorated_function
