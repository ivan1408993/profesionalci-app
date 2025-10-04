from flask import Blueprint, render_template, request, session, redirect, url_for, flash, g, current_app
from flask_babel import _
from flask_mail import Message
from flask_paginate import Pagination, get_page_args

from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import or_, and_, func
from sqlalchemy.orm import joinedload
from flask import make_response

from app import db
from app.models import Employer, Driver, DriverCard, Rating
from app.utils import hash_jmbg, generate_salt, hash_jmbg_with_salt, generate_reset_token, verify_reset_token, add_new_driver_card
from app.helpers import konvertuj_tekst
from app.decorators import login_required, superadmin_required

from datetime import datetime, timedelta
import os
import hashlib
from .models import LoginAttempt


main = Blueprint('main', __name__)


def generate_salt():
    return os.urandom(16)

def hash_jmbg_with_salt(jmbg: str, salt: bytes) -> str:
    return hashlib.sha256(salt + jmbg.encode('utf-8')).hexdigest()



def add_new_driver_card(driver, new_card_number, expiry_date=None):
    # Deaktiviraj sve prethodne kartice
    for card in driver.cards:
        card.is_active = False

    # Dodaj novu kao aktivnu
    new_card = DriverCard(
        card_number=new_card_number,
        driver_id=driver.id,
        is_active=True,
        expiry_date=expiry_date
    )
    db.session.add(new_card)
    db.session.commit()
    return new_card

@main.route('/drivers/<int:driver_id>/add_card', methods=['GET', 'POST'])
def add_driver_card(driver_id):
    employer_id = session.get('user_id')
    if not employer_id:
        flash(_("Morate biti prijavljeni kao poslodavac."))
        return redirect(url_for('main.login'))

    driver = Driver.query.get_or_404(driver_id)

    if request.method == 'POST':
        new_card_number = request.form.get('card_number', '').strip()
        issue_date_str = request.form.get('issue_date', '').strip()
        expiry_date_str = request.form.get('expiry_date', '').strip()

        # Provera datuma
        issue_date = None
        expiry_date = None

        if issue_date_str:
            try:
                issue_date = datetime.strptime(issue_date_str, '%Y-%m-%d').date()
            except ValueError:
                flash(_("Neispravan format datuma izdavanja."))
                return redirect(url_for('main.add_driver_card', driver_id=driver.id))

        if expiry_date_str:
            try:
                expiry_date = datetime.strptime(expiry_date_str, '%Y-%m-%d').date()
            except ValueError:
                flash(_("Neispravan format datuma isteka."))
                return redirect(url_for('main.add_driver_card', driver_id=driver.id))

        # Provera da li kartica već postoji (jedinstveni broj)
        existing_card = DriverCard.query.filter_by(card_number=new_card_number).first()
        if existing_card:
            flash(_("Ova kartica već postoji u sistemu."))
            return redirect(url_for('main.add_driver_card', driver_id=driver.id))

        # Dodaj novu karticu i deaktiviraj prethodne
        add_new_driver_card(driver, new_card_number, issue_date, expiry_date)
        flash(_("Nova kartica je uspešno dodata i aktivirana."))
        return redirect(url_for('main.driver_detail', driver_id=driver.id))  # ili neka stranica sa detaljima vozača

    return render_template('add_card.html', driver=driver)


# INDEX
@main.route('/')
def index():
    # Pročitaj cookie-je
    user_id = request.cookies.get('user_id')
    user_type = request.cookies.get('user_type')

    if user_id and user_type:
        if user_type == 'employer':
            return redirect(url_for('main.drivers'))
        elif user_type == 'superadmin':
            return redirect(url_for('main.admin_dashboard'))

    # Ako nema cookie ili nije validan, prikaži index
    return render_template(
        'index.html',
        current_lang=request.cookies.get('lang', 'sr')
    )


@main.route('/drivers/add', methods=['GET', 'POST'])
def add_driver():
    employer_id = session.get('user_id')
    if not employer_id:
        flash(_("Molimo prijavite se kao poslodavac."))
        return redirect(url_for('main.login'))

    current_date = datetime.today().strftime('%Y-%m-%d')
    if request.method == 'POST':
        full_name = request.form['full_name'].strip()
        jmbg = request.form['jmbg'].strip()
        cpc_card_number = request.form.get('cpc_card_number', '').strip()
        cpc_expiry_date_str = request.form.get('cpc_expiry_date', '').strip()
        card_number = request.form.get('card_number', '').strip()
        issue_date_str = request.form.get('issue_date', '').strip()
        expiry_date_str = request.form.get('expiry_date', '').strip()

        # --- Provere ---
        if len(jmbg) != 13 or not jmbg.isdigit():
            flash(_("JMBG mora sadržati tačno 13 cifara."))
            return redirect(url_for('main.add_driver'))

        if not cpc_card_number or len(cpc_card_number) != 9:
            flash(_("Broj CPC kartice je obavezan i mora imati tačno 9 karaktera."))
            return redirect(url_for('main.add_driver'))

        if not cpc_card_number.startswith("ABS") or not cpc_card_number[3:].isdigit():
            flash(_("Broj CPC kartice mora početi sa 'ABS' i imati 6 cifara posle toga."))
            return redirect(url_for('main.add_driver'))

        if card_number and len(card_number) != 16:
            flash(_("Broj tahograf kartice mora imati tačno 16 karaktera."))
            return redirect(url_for('main.add_driver'))

        # Datumi
        issue_date = datetime.strptime(issue_date_str, '%Y-%m-%d').date() if issue_date_str else None
        expiry_date = datetime.strptime(expiry_date_str, '%Y-%m-%d').date() if expiry_date_str else None
        cpc_expiry_date = datetime.strptime(cpc_expiry_date_str, '%Y-%m-%d').date() if cpc_expiry_date_str else None

        # Provera da li CPC kartica već postoji
        existing_cpc = Driver.query.filter_by(cpc_card_number=cpc_card_number).first()
        if existing_cpc:
            flash(_("Ova CPC kartica već postoji u sistemu."))
            return redirect(url_for('main.add_driver'))

        # Provera postojećeg vozača po JMBG
        existing_driver = None
        all_drivers = Driver.query.all()
        for driver in all_drivers:
            if hash_jmbg_with_salt(jmbg, driver.salt) == driver.jmbg_hashed:
                existing_driver = driver
                break

        if existing_driver:
            if existing_driver.active and existing_driver.employer_id == employer_id:
                flash(_("Vozač već radi kod vas."))
                return redirect(url_for('main.drivers'))

            elif existing_driver.active and existing_driver.employer_id != employer_id:
                flash(_("Vozač već radi kod drugog poslodavca."))
                return redirect(url_for('main.search_driver'))

            else:
                # Update inactive vozača
                existing_driver.full_name = full_name
                existing_driver.employer_id = employer_id
                existing_driver.cpc_card_number = cpc_card_number
                existing_driver.cpc_expiry_date = cpc_expiry_date
                existing_driver.active = True
                db.session.commit()

                if card_number:
                    existing_card = DriverCard.query.filter_by(card_number=card_number).first()
                    if existing_card:
                        flash(_("Tahograf kartica sa ovim brojem već postoji u sistemu."))
                        return redirect(url_for('main.add_driver'))

                    new_card = DriverCard(
                        card_number=card_number,
                        driver_id=existing_driver.id,
                        is_active=True,
                        issue_date=issue_date,
                        expiry_date=expiry_date,
                    )
                    db.session.add(new_card)
                    db.session.commit()

                flash(_("Postojeći vozač je preuzet u vašu firmu."))
                return redirect(url_for('main.drivers'))

        # Dodavanje novog vozača
        salt = generate_salt()
        jmbg_hashed = hash_jmbg_with_salt(jmbg, salt)

        new_driver = Driver(
            full_name=full_name,
            jmbg_hashed=jmbg_hashed,
            salt=salt,
            cpc_card_number=cpc_card_number,
            cpc_expiry_date=cpc_expiry_date,
            employer_id=employer_id,
            active=True
        )
        db.session.add(new_driver)
        db.session.commit()

        if card_number:
            new_card = DriverCard(
                card_number=card_number,
                driver_id=new_driver.id,
                is_active=True,
                issue_date=issue_date,
                expiry_date=expiry_date
            )
            db.session.add(new_card)
            db.session.commit()

        flash(_("Novi vozač je uspešno dodat."))
        return redirect(url_for('main.drivers'))

    return render_template('add_driver.html', current_lang=session.get('lang', 'sr'), current_date=current_date)

@main.route('/drivers/search', methods=['GET', 'POST'])
def search_driver():
    employer_id = session.get('user_id')
    if not employer_id:
        flash(_("Morate biti prijavljeni kao poslodavac."))
        return redirect(url_for('main.login'))

    driver = None
    ratings_info = []
    show_additional_fields = False

    if request.method == 'POST':
        search_input = request.form.get('search_input', '').strip()
        print(f"🔍 Pretraga za unetim: {search_input}")

        if search_input.isdigit() and len(search_input) == 13:
            # Pretraga po JMBG
            from app.utils import hash_jmbg_with_salt
            all_drivers = Driver.query.all()
            for d in all_drivers:
                hashed = hash_jmbg_with_salt(search_input, d.salt)
                if hashed == d.jmbg_hashed:
                    driver = d
                    break
            print(f"🔎 Pronađen vozač po JMBG: {driver}")
        
        if not driver:
            # Pretraga po broju tahograf kartice
            card = DriverCard.query.filter_by(card_number=search_input).first()
            print(f"🔎 Pronađena tahograf kartica: {card}")
            if card:
                driver = card.driver

        if not driver:
            # Pretraga po broju CPC kartice
            cpc_card_number = Driver.query.filter_by(cpc_card_number=search_input).first()
            print(f"🔎 Pronađena CPC kartica: {cpc_card_number}")
            if cpc_card_number:
                driver = cpc_card_number

        if not driver:
            flash(_("Vozač sa unetim podacima nije pronađen."))
            show_additional_fields = True
        else:
            for r in driver.ratings:
                employer = Employer.query.get(r.employer_id)
                ratings_info.append({
                    'employer_name': employer.company_name if employer else "Nepoznat poslodavac",
                    'stars': r.stars,
                    'comment': r.comment,
                    'rated_at': r.created_at.strftime('%d.%m.%Y') if r.created_at else ''
                })

    already_employed_by_other = False
    if driver:
        already_employed_by_other = (
            driver.employer_id and not driver.active and driver.employer_id != employer_id
        )

    return render_template('search_driver.html',
                           driver=driver,
                           ratings_info=ratings_info,
                           already_employed_by_other=already_employed_by_other,
                           show_additional_fields=show_additional_fields,
                           current_lang=session.get('lang', 'sr'))



@main.route('/adopt_driver/<int:driver_id>', methods=['POST'])
def adopt_driver(driver_id):
    if 'user_id' not in session or session.get('user_type') != 'employer':
        flash(_('Nemate dozvolu za ovu akciju.'), 'danger')
        return redirect(url_for('main.login'))

    driver = Driver.query.get_or_404(driver_id)
    employer_id = session['user_id']

    if driver.employer_id == employer_id:
        if not driver.active:
            driver.active = True
            db.session.commit()
            flash(_('Vozač je ponovo aktiviran u vašem sistemu.'), 'success')
        else:
            flash(_('Vozač je već kod vas i aktivan je.'), 'info')
        return redirect(url_for('main.drivers', driver_id=driver.id))

    # Ako je vozač aktivan kod drugog poslodavca - NE DOZVOLJAVAMO preuzimanje
    if driver.active and driver.employer_id != employer_id:
        flash(_('Vozač je već aktivan kod drugog poslodavca i ne može se preuzeti.'), 'warning')
        return redirect(url_for('main.driver_detail', driver_id=driver.id))

    # Vozač nije aktivan ili nema poslodavca, može se preuzeti
    driver.employer_id = employer_id
    driver.active = True
    db.session.commit()

    flash(_(f'Vozač {driver.full_name} je uspešno preuzet u vašu firmu.'), 'success')
    return redirect(url_for('main.driver_detail', driver_id=driver.id))




@main.route('/profile', methods=['GET', 'POST'])
def employer_profile():
    if session.get('user_type') != 'employer':
        flash(_("Nemate pristup ovoj stranici."))
        return redirect(url_for('main.index'))

    employer_id = session.get('user_id')
    employer = Employer.query.get_or_404(employer_id)

    if request.method == 'POST':
        employer.company_name = request.form['company_name']
        employer.email = request.form['email']

        phone_number = request.form.get('phone_number', '').strip()
        if phone_number and not phone_number.isdigit():
            flash(_("Broj telefona može sadržati samo cifre."))
            return redirect(url_for('main.employer_profile'))

        employer.phone_number = phone_number

        new_password = request.form.get('password')
        if new_password:
            employer.password_hash = generate_password_hash(new_password)

        db.session.commit()
        flash(_("Podaci su uspešno ažurirani."))
        return redirect(url_for('main.drivers'))

    return render_template('employer_profile.html', employer=employer, current_lang=session.get('lang', 'sr'))



@main.route('/drivers/<int:driver_id>/activate', methods=['POST'])
def activate_existing_driver(driver_id):
    employer_id = session.get('user_id')
    if not employer_id:
        flash(_("Molimo prijavite se."))
        return redirect(url_for('main.login'))

    driver = Driver.query.get_or_404(driver_id)

    # Ako je već aktivan kod drugog poslodavca → zabrana
    if driver.active and driver.employer_id != employer_id:
        flash(_("Ovaj vozač je trenutno zaposlen kod drugog poslodavca i ne možete ga preuzeti."))
        return redirect(url_for('main.drivers'))

    # Ako je već kod ovog poslodavca → samo osiguraj da je aktivan
    if driver.employer_id == employer_id:
        driver.active = True
        db.session.commit()
        flash(_(f"Vozač {driver.full_name} je sada aktivan kod vaše firme."))
        return redirect(url_for('main.drivers'))

    # Ako je neaktivan → preuzmi i aktiviraj
    driver.employer_id = employer_id
    driver.active = True
    db.session.commit()
    flash(_(f"Vozač {driver.full_name} je uspešno dodat vašoj firmi."))
    return redirect(url_for('main.drivers'))

# REGISTER
@main.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        company_name = request.form['company_name'].strip()
        pib = request.form['pib'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        phone_number = request.form['phone_number'].strip()  # ново поље
        password_hash = generate_password_hash(password)

        # Validacija PIB
        if not pib.isdigit() or len(pib) != 9:
            flash(_("PIB mora sadržati tačno 9 cifara."))
            return redirect(url_for('main.register'))

        # Validacija telefona - samo cifre, нпр. 6 до 15 цифара
        if not phone_number.isdigit() or not (6 <= len(phone_number) <= 15):
            flash(_("Telefon mora sadržati samo cifre i imati između 6 i 15 cifara."))
            return redirect(url_for('main.register'))

        # Provera da li već postoji firma sa istim PIB-om
        existing_pib = Employer.query.filter_by(pib=pib).first()
        if existing_pib:
            if not existing_pib.active:
                flash(_("Firma sa ovim PIB-om nije aktivna. Registracija nije moguća."))
                return redirect(url_for('main.register'))
            else:
                flash(_("Postoji već nalog sa tim PIB-om."))
                return redirect(url_for('main.register'))

        # PROVERA DA LI MEJL VEĆ POSTOJI
        existing_email = Employer.query.filter_by(email=email).first()
        if existing_email:
            flash(_("E-mail adresa već postoji u sistemu. Izaberite drugu."))
            return redirect(url_for('main.register'))

        # Ako je sve u redu, dodaj novog poslodavca
        new_employer = Employer(
            company_name=company_name,
            pib=pib,
            email=email,
            password_hash=password_hash,
            phone_number=phone_number,
            active=True
        )
        db.session.add(new_employer)
        db.session.commit()

        # --- Dodato: Slanje email obaveštenja adminu ---
        try:
            admin_email = current_app.config.get('MAIL_USERNAME')
            msg = Message(
                subject="Nova registracija poslodavca",
                sender=current_app.config.get('MAIL_DEFAULT_SENDER'),
                recipients=[admin_email]
            )
            msg.body = (
                f"Registrovan je novi poslodavac:\n\n"
                f"Naziv firme: {company_name}\n"
                f"PIB: {pib}\n"
                f"E-mail: {email}\n"
                f"Telefon: {phone_number}"
            )
            mail.send(msg)
        except Exception as e:
            # Opcionalno: loguj grešku, ali ne prekidaj registraciju
            print(f"Greška pri slanju mejla: {e}")

        flash(_("Uspešna registracija. Sada se možete prijaviti."))
        return redirect(url_for('main.login'))

    return render_template('register.html', current_lang=session.get('lang', 'sr'))



@main.route('/logout')
def logout():
    # Uzmemo jezik iz cookie-ja (ako postoji), fallback na 'sr'
    lang = request.cookies.get('lang', 'sr')

    # Očistimo sesiju
    session.clear()

    # Kreiramo response i brišemo login cookie-je
    response = make_response(redirect(url_for('main.index')))
    response.set_cookie('lang', lang, max_age=60*60*24*30)  # čuvamo 30 dana

    # Brišemo login cookie-je
    response.set_cookie('user_id', '', expires=0, domain='.driverrate.com')
    response.set_cookie('user_type', '', expires=0, domain='.driverrate.com')
    response.set_cookie('company_name', '', expires=0, domain='.driverrate.com')

    return response


@main.route('/login', methods=['GET', 'POST'])
def login():
    # helper: stvarni IP (iza proxy-ja)
    xff = (request.headers.get('X-Forwarded-For') or "").split(",")[0].strip()
    ip = xff or request.remote_addr or "unknown"

    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        # Tražimo po EMAILU samo
        attempt = LoginAttempt.query.filter_by(email=email).first()

        # Ako postoji blokada
        if attempt and attempt.attempts >= 5:
            if attempt.last_failed_at and (datetime.utcnow() - attempt.last_failed_at) < timedelta(minutes=5):
                remaining = 300 - int((datetime.utcnow() - attempt.last_failed_at).total_seconds())
                return render_template(
                    "login.html",
                    current_lang=request.cookies.get('lang', 'sr'),
                    block=True,
                    remaining_attempts=0,
                    remaining_seconds=remaining,
                    email=email
                )
            else:
                attempt.attempts = 0
                attempt.last_failed_at = datetime.utcnow()
                db.session.commit()

        employer = Employer.query.filter_by(email=email).first()

        if employer and check_password_hash(employer.password_hash, password):
            if not employer.active:
                flash(_("Vaša firma nije aktivna. Prijava nije moguća."))
                remaining_attempts = 5 - (attempt.attempts if attempt else 0)
                return render_template(
                    "login.html",
                    current_lang=request.cookies.get('lang', 'sr'),
                    block=False,
                    remaining_attempts=remaining_attempts,
                    remaining_seconds=0,
                    email=email
                )

            # uspešan login → očisti attempt zapis
            if attempt:
                db.session.delete(attempt)
                db.session.commit()

            # --- napravimo response sa cookie ---
            resp = make_response(
                redirect(url_for('main.admin_dashboard' if employer.is_superadmin else 'main.drivers'))
            )

            # Autentikacioni cookie
            resp.set_cookie(
                'user_id',
                str(employer.id),
                domain='.driverrate.com',  # važi za www i non-www
                secure=True,               # HTTPS obavezno
                httponly=True,             # JS ne može da čita
                samesite='Lax',
                max_age=30*24*3600         # 30 dana
            )

            # User role cookie (ako front-end treba da zna)
            resp.set_cookie(
                'user_type',
                'superadmin' if employer.is_superadmin else 'employer',
                domain='.driverrate.com',
                secure=True,
                httponly=False,   # JS može da čita
                samesite='Lax',
                max_age=30*24*3600
            )

            # Company name cookie
            resp.set_cookie(
                'company_name',
                employer.company_name,
                domain='.driverrate.com',
                secure=True,
                httponly=False,
                samesite='Lax',
                max_age=30*24*3600
            )

            return resp

        # Neuspešan login → uvećaj broj pokušaja
        now = datetime.utcnow()
        if attempt:
            attempt.attempts += 1
            attempt.last_failed_at = now
        else:
            attempt = LoginAttempt(email=email, ip_address=ip, attempts=1, last_failed_at=now)
            db.session.add(attempt)

        db.session.commit()

        remaining_attempts = max(0, 5 - attempt.attempts)
        if remaining_attempts > 0:
            flash(_("Pogrešan email ili lozinka. Preostalo pokušaja: ") + str(remaining_attempts))
            return render_template(
                "login.html",
                current_lang=request.cookies.get('lang', 'sr'),
                block=False,
                remaining_attempts=remaining_attempts,
                remaining_seconds=0,
                email=email
            )
        else:
            return render_template(
                "login.html",
                current_lang=request.cookies.get('lang', 'sr'),
                block=True,
                remaining_attempts=0,
                remaining_seconds=300,
                email=email
            )

    # GET – početno stanje
    return render_template(
        "login.html",
        current_lang=request.cookies.get('lang', 'sr'),
        block=False,
        remaining_attempts=5,
        remaining_seconds=0,
        email=""
    )


@main.route('/dashboard')
def dashboard():
    # Uzmemo company_name iz sesije
    company_name = session.get('company_name')
    if not company_name:
        # Ako nema podataka u sesiji, redirekt na prijavu
        flash(_("Molimo prijavite se."))
        return redirect(url_for('main.login'))

    return render_template('dashboard.html', company_name=company_name, current_lang=session.get('lang', 'sr'))


@main.route('/drivers')
def drivers():
    employer_id = session.get('user_id')
    if not employer_id:
        flash(_("Molimo prijavite se."))
        return redirect(url_for('main.login'))

    employer = Employer.query.get(employer_id)
    if not employer:
        flash(_("Greška pri autentikaciji."))
        return redirect(url_for('main.login'))

    search = request.args.get('search', '').strip()
    page = request.args.get('page', 1, type=int)
    per_page = 20

    # Novi parametri za filter i sortiranje
    active_only = request.args.get('active', default='1') == '1'
    sort = request.args.get('sort', 'ime')

    # Osnovni query - samo vozači za datog poslodavca
    drivers_query = Driver.query.options(
    db.joinedload(Driver.cards)
    ).filter_by(employer_id=employer.id)


    # Ako checkbox "samo aktivni" -> filtriraj
    if active_only:
        drivers_query = drivers_query.filter(Driver.active == True)

    # Pretraga
    if search:
        drivers_query = drivers_query.filter(
            or_(
                Driver.full_name.ilike(f'%{search}%'),
                Driver.cpc_card_number.ilike(f'%{search}%'),
                Driver.cards.any(DriverCard.card_number.ilike(f'%{search}%'))
            )
        )

    # Sortiranje
    if sort == 'ocena':
        avg_rating_subq = db.session.query(
            Rating.driver_id,
            func.avg(Rating.stars).label('avg_stars')
        ).group_by(Rating.driver_id).subquery()

        drivers_query = drivers_query.outerjoin(
            avg_rating_subq,
            Driver.id == avg_rating_subq.c.driver_id
        ).order_by(
            avg_rating_subq.c.avg_stars.desc().nullslast(),
            Driver.full_name.asc()
        )
    else:
        drivers_query = drivers_query.order_by(Driver.full_name.asc())

    pagination = drivers_query.paginate(page=page, per_page=per_page, error_out=False)
    drivers_list = pagination.items

    # Prosečne ocene
    driver_ratings = {}
    for d in drivers_list:
        avg_rating = db.session.query(func.avg(Rating.stars)).filter(Rating.driver_id == d.id).scalar()
        driver_ratings[d.id] = round(avg_rating, 2) if avg_rating else None

    return render_template(
        'drivers.html',
        drivers=drivers_list,
        driver_ratings=driver_ratings,
        search=search,
        pagination=pagination,
        active_only=active_only,
        sort=sort,
        current_lang=session.get('lang', 'sr')
    )

@main.route('/drivers/search_card', methods=['GET', 'POST'])
def search_driver_by_card():
    company_name = session.get('company_name')
    if not company_name:
        flash(_("Molimo prijavite se."))
        return redirect(url_for('main.login'))

    employer = Employer.query.filter_by(company_name=company_name).first()
    if not employer:
        flash(_("Greška pri autentikaciji."))
        return redirect(url_for('main.login'))

    if request.method == 'POST':
        card_number = request.form['card_number'].strip()

        driver = Driver.query.filter_by(card_number=card_number).first()

        if not driver:
            flash(_("Vozač sa datim brojem tahograf kartice ne postoji."))
            return redirect(url_for('main.search_driver_by_card'))

        # Ako vozač nije trenutno kod ovog poslodavca, prikaži mu detalje gde je sve radio
        if driver.employer_id != employer.id:
            # Uzmi sve poslodavce kod kojih je vozač radio (možda sa drugim tablama ako postoje)
            # Ako nemaš istoriju poslodavaca, možda moraš da dodaš
            # Za sada ćemo samo prikazati vozača i poruku
            return render_template('driver_exists.html', driver=driver, employer=employer, current_lang=session.get('lang', 'sr'))

        # Ako je vozač trenutno kod ovog poslodavca - preusmeri ga na listu vozača ili detalje
        flash(_("Vozač već radi u vašoj firmi."))
        return redirect(url_for('main.drivers'))

    return render_template('search_driver.html', current_lang=session.get('lang', 'sr'))


@main.route('/drivers/<int:driver_id>/exists', methods=['GET'])
def driver_exists(driver_id):
    employer_id = session.get('user_id')
    if not employer_id:
        flash(_("Molimo prijavite se."))
        return redirect(url_for('main.login'))

    driver = Driver.query.get_or_404(driver_id)

    # Uzimanje svih ocena i podataka o poslodavcima kod kojih je vozač radio
    ratings_query = (
        db.session.query(Rating, Employer.company_name)
        .join(Employer, Rating.employer_id == Employer.id)
        .filter(Rating.driver_id == driver.id)
        .order_by(Rating.rated_at.desc())
    ).all()

    ratings_info = []
    for rating, employer_name in ratings_query:
        ratings_info.append({
            'employer_name': employer_name,
            'stars': rating.stars,
            'comment': rating.comment,
            'rated_at': rating.rated_at.strftime('%d.%m.%Y') if rating.rated_at else ''
        })

    return render_template('driver_exists.html', driver=driver, ratings_info=ratings_info, current_lang=session.get('lang', 'sr'))


@main.route('/deactivate_driver/<int:driver_id>', methods=['POST'])
def deactivate_driver(driver_id):
    employer_id = session.get('user_id')
    if not employer_id or session.get('user_type') != 'employer':
        flash(_("Morate biti prijavljeni kao poslodavac."))
        return redirect(url_for('main.login'))

    driver = Driver.query.get_or_404(driver_id)

    # Proverimo da li postoji ocena
    existing_rating = Rating.query.filter_by(driver_id=driver_id, employer_id=employer_id).first()
    if not existing_rating:
        flash(_("Morate prvo oceniti vozača pre nego što ga označite kao neaktivnog."))
        return redirect(url_for('main.rate_driver', driver_id=driver_id))

    # Ako već postoji ocena – nastavljamo sa deaktivacijom
    driver.active = False
    db.session.commit()
    db.session.refresh(driver)  # Osvježi objekat iz baze
    print(f"Status vozača nakon deaktivacije: active = {driver.active}")

    
    full_name = driver.full_name

    flash(_(f"Vozač {full_name} je uspešno označen kao neaktivan."))
    return redirect(url_for('main.drivers', active=1))


@main.route('/drivers/all')
def all_drivers():
    employer_id = session.get('user_id')
    if not employer_id:
        flash(_("Molimo prijavite se."))
        return redirect(url_for('main.login'))

    search = request.args.get('search', '').strip()
    page = request.args.get('page', 1, type=int)

    # Filtriraj sve vozače koji su radili kod prijavljenog poslodavca, bez obzira na status
    drivers_query = Driver.query.filter_by(employer_id=employer_id)

    if search:
        # Pretraga po imenu, broju tahograf kartice i CPC kartici
        drivers_query = drivers_query.filter(
            (Driver.full_name.ilike(f'%{search}%')) |
            (Driver.cards.any(DriverCard.card_number.ilike(f'%{search}%'))) |
            (Driver.cpc_card_number.ilike(f'%{search}%'))
        )

    # Paginacija
    pagination = drivers_query.order_by(Driver.full_name).paginate(page=page, per_page=10, error_out=False)
    drivers_list = pagination.items

    # Izračunaj prosečnu ocenu za svakog vozača
    from sqlalchemy import func
    driver_ratings = {}
    for d in drivers_list:
        avg_rating = db.session.query(func.avg(Rating.stars)).filter(Rating.driver_id == d.id).scalar()
        driver_ratings[d.id] = round(avg_rating, 2) if avg_rating else None

    return render_template(
        'all_drivers.html',
        drivers=drivers_list,
        driver_ratings=driver_ratings,
        search=search,
        pagination=pagination,
        current_lang=session.get('lang', 'sr')
    )


# Ruta za prikaz forme za ocenjivanje vozaca
@main.route('/drivers/<int:driver_id>/rate', methods=['GET', 'POST'])
def rate_driver(driver_id):
    # Provera da li je prijavljen poslodavac
    employer_id = session.get('user_id')
    if not employer_id:
        flash(_("Morate biti prijavljeni kao poslodavac da biste ocenili vozača."))
        return redirect(url_for('main.login'))

    driver = Driver.query.get_or_404(driver_id)

    # Proverimo da li već postoji ocena ovog vozača od ovog poslodavca
    existing_rating = Rating.query.filter_by(driver_id=driver_id, employer_id=employer_id).first()

    if request.method == 'POST':
        rating_value = int(request.form['rating'])
        comment = request.form['comment']

        if existing_rating:
            # Ažuriraj postojeću ocenu
            existing_rating.stars = rating_value
            existing_rating.comment = comment
            existing_rating.created_at = datetime.utcnow()
            flash(_('Ocena je uspešno ažurirana.'))
        else:
            # Kreiraj novu ocenu
            new_rating = Rating(
                driver_id=driver_id,
                employer_id=employer_id,
                stars=rating_value,
                comment=comment
            )
            db.session.add(new_rating)
            flash(_('Ocena je uspešno dodata.'))

        db.session.commit()
        return redirect(url_for('main.drivers'))

    return render_template('rate_driver.html', driver=driver, existing_rating=existing_rating, current_lang=session.get('lang', 'sr'))

@main.route('/drivers/<int:driver_id>')
def driver_detail(driver_id):
    # ✅ Dozvoljen pristup samo poslodavcima
    if session.get('user_type') != 'employer' or not session.get('user_id'):
        flash(_("Morate biti prijavljeni kao poslodavac."), "warning")
        return redirect(url_for('main.login'))

    driver = Driver.query.options(
        joinedload(Driver.cards),
        joinedload(Driver.ratings).joinedload(Rating.employer)
    ).get_or_404(driver_id)

    # ✅ Dozvoljeno menjanje samo ako je ovaj poslodavac aktivni poslodavac vozača
    currently_employed_by_this_employer = (
        driver.active and driver.employer_id == session.get('user_id')
    )

    # ✅ Pretraga po firmi ili PIB-u
    q = request.args.get("q", "").strip()

    ratings = driver.ratings
    if q:
        ratings = [
            r for r in ratings if r.employer and (
                (r.employer.company_name and q.lower() in r.employer.company_name.lower()) or
                (r.employer.pib and q.lower() in r.employer.pib.lower())
            )
        ]

    return render_template(
        'driver_detail.html',
        driver=driver,
        ratings=ratings,
        can_update_driver=currently_employed_by_this_employer,
        q=q
    )



@main.route('/reset-password', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form['email']
        employer = Employer.query.filter_by(email=email).first()
        if employer:
            token = generate_reset_token(email)
            reset_url = url_for('main.reset_password_token', token=token, _external=True)
            
            # ✅ Zamena flash linka slanjem mejla
            send_reset_email(email, reset_url)
        
        # Uvek vraćamo istu poruku radi bezbednosti
        flash(_("Ako email postoji u sistemu, link za reset je poslat."), 'info')
        return redirect(url_for('main.login'))

    return render_template('reset_password_request.html', current_lang=session.get('lang', 'sr'))


@main.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password_token(token):
    email = verify_reset_token(token)
    if not email:
        flash(_('Link nije validan ili je istekao.'), 'danger')
        return redirect(url_for('main.login'))

    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form.get('confirm_password')

        # Provera da li se lozinke poklapaju
        if new_password != confirm_password:
            flash(_("Lozinke se ne poklapaju."), "danger")
            return redirect(url_for('main.reset_password_token', token=token))

        employer = Employer.query.filter_by(email=email).first()
        if employer:
            employer.password_hash = generate_password_hash(new_password)
            db.session.commit()
            flash(_('Lozinka je uspešno promenjena.'), 'success')
            return redirect(url_for('main.login'))

    return render_template('reset_password_form.html', token=token, current_lang=session.get('lang', 'sr'))


from flask_mail import Message
from app import mail  # iz tvoje aplikacije

def send_reset_email(to_email, reset_url):
    msg = Message("Resetovanje lozinke", recipients=[to_email])
    msg.body = f"""Zdravo,

Zatražili ste resetovanje lozinke. Kliknite ili nalepite sledeći link u pregledač:

{reset_url}

Ako niste Vi tražili reset, slobodno ignorišite ovaj mejl.
"""
    mail.send(msg)


from flask_login import login_required, current_user

@main.route('/admin/firme')
@login_required
def sve_firme():
    if not current_user.is_superadmin:
        flash(_("Nemate pristup ovoj stranici."), "danger")
        return redirect(url_for('index'))

    from models import Employer  # ili kako ti je naziv modela za poslodavce
    sve_firme = Employer.query.all()
    return render_template('admin_firme.html', firme=sve_firme, current_lang=session.get('lang', 'sr'))


@main.route('/admin/dashboard')
def admin_dashboard():
    if session.get('user_type') != 'superadmin':
        flash(_("Nemate pristup ovoj stranici."))
        return redirect(url_for('main.login'))

    # Pretraga firmi
    company_query = request.args.get('company_query', '').strip()
    pib_query = request.args.get('pib_query', '').strip()

    # Pretraga vozača
    driver_query = request.args.get('driver_query', '').strip()

    # Filtriranje firmi po imenu i PIB-u
    employers = Employer.query
    if company_query:
        employers = employers.filter(Employer.company_name.ilike(f'%{company_query}%'))
    if pib_query:
        employers = employers.filter(Employer.pib.ilike(f'%{pib_query}%'))
    employers = employers.all()

    # Filtriranje vozača po imenu, tahograf kartici (u DriverCard) i CPC broju
    drivers = Driver.query
    if driver_query:
        like_pattern = f'%{driver_query}%'
        # Pravimo join sa DriverCard tabelom radi pretrage po card_number
        drivers = drivers.join(Driver.cards).filter(
            (Driver.full_name.ilike(like_pattern)) |
            (Driver.cpc_card_number.ilike(like_pattern)) |
            (DriverCard.card_number.ilike(like_pattern))
        ).distinct()

    drivers = drivers.all()

    ratings = Rating.query.all()

    return render_template(
        'admin/dashboard.html',
        employers=employers,
        drivers=drivers,
        ratings=ratings,
        company_query=company_query,
        pib_query=pib_query,
        driver_query=driver_query,
        current_lang=session.get('lang', 'sr')
    )



@main.route('/admin/employer/<int:employer_id>/drivers')
def admin_employer_drivers(employer_id):
    if session.get('user_type') != 'superadmin':
        flash(_("Nemate pristup ovoj stranici."))
        return redirect(url_for('main.login'))

    employer = Employer.query.get_or_404(employer_id)
    drivers = Driver.query.filter_by(employer_id=employer.id).all()

    return render_template('admin/employer_drivers.html', employer=employer, drivers=drivers, current_lang=session.get('lang', 'sr'))


@main.route('/change_language', methods=['POST'])
def change_language():
    lang = request.form.get('language', 'sr')          # 'sr', 'en', ...
    script = request.form.get('script', 'cyrillic')    # 'latin' ili 'cyrillic', podrazumevano ćirilica

    session['lang'] = lang
    session['script'] = script

    return redirect(request.referrer or url_for('main.index'))


@main.route('/admin/employer/<int:employer_id>/toggle_status')
def toggle_employer_status(employer_id):
    if session.get('user_type') != 'superadmin':
        flash(_("Nemate pristup ovoj akciji."))
        return redirect(url_for('main.login'))

    employer = Employer.query.get_or_404(employer_id)
    employer.active = not employer.active
    db.session.commit()

    flash(_(f"Status firme '{employer.company_name}' je uspešno promenjen."))
    return redirect(url_for('main.admin_dashboard'))


from datetime import datetime

@main.before_request
def before_request():
    g.current_lang = session.get('lang') or request.cookies.get('lang') or 'sr'


@main.route('/drivers/<int:driver_id>/update', methods=['GET', 'POST'])
def update_driver(driver_id):
    # Provera da li je poslodavac prijavljen
    employer_id = session.get('user_id')
    if not employer_id:
        flash(_("Morate biti prijavljeni kao poslodavac."), "danger")
        return redirect(url_for('main.login'))

    # Učitavanje vozača
    driver = Driver.query.get_or_404(driver_id)
    current_date = datetime.today().strftime('%Y-%m-%d')

    # Provera prava pristupa: vozač mora biti aktivan i pripadati poslodavcu
    if not driver.active or driver.employer_id != employer_id:
        flash(_("Nemate dozvolu da ažurirate ovog vozača."), "danger")
        return redirect(url_for('main.driver_detail', driver_id=driver_id))

    # Pronalazak aktivne tahograf kartice
    current_card = next((card for card in driver.cards if card.is_active), None)

    if request.method == 'POST':
        # Prikupljanje podataka iz forme
        new_full_name = request.form.get('full_name', '').strip()
        new_card_number = request.form.get('card_number', '').strip()
        expiry_date_str = request.form.get('expiry_date', '').strip()
        cpc_card_number = request.form.get('cpc_card_number', '').strip()
        cpc_expiry_date_str = request.form.get('cpc_expiry_date', '').strip()

        # Validacija imena
        if not (2 <= len(new_full_name) <= 100):
            flash(_("Ime i prezime mora imati između 2 i 100 karaktera."), "warning")
            return redirect(url_for('main.update_driver', driver_id=driver.id))

        # Validacija CPC kartice
        import re
        if not re.fullmatch(r'^ABS[0-9]{6}$', cpc_card_number):
            flash(_("Broj CPC kartice mora početi sa ABS i imati ukupno 9 karaktera (ABS + 6 cifara)."), "danger")
            return redirect(url_for('main.update_driver', driver_id=driver.id))

        # Parsiranje datuma
        try:
            expiry_date = datetime.strptime(expiry_date_str, '%Y-%m-%d').date() if expiry_date_str else None
            cpc_expiry_date = datetime.strptime(cpc_expiry_date_str, '%Y-%m-%d').date() if cpc_expiry_date_str else None
        except ValueError:
            flash(_("Neispravan format datuma."), "warning")
            return redirect(url_for('main.update_driver', driver_id=driver.id))

        # Ažuriranje imena
        driver.full_name = new_full_name

        # Tahograf kartica
        if new_card_number:
            if not re.fullmatch(r'^[A-Za-z0-9]{16}$', new_card_number):
                flash(_("Broj tahograf kartice mora imati tačno 16 karaktera, slova ili cifara."), "danger")
                return redirect(url_for('main.update_driver', driver_id=driver.id))

            existing_card = DriverCard.query.filter(
                DriverCard.card_number == new_card_number,
                DriverCard.driver_id != driver.id
            ).first()
            if existing_card:
                flash(_("Ovaj broj tahograf kartice je već dodeljen drugom vozaču."), "danger")
                return redirect(url_for('main.update_driver', driver_id=driver.id))

            # Deaktivacija stare kartice
            if current_card:
                current_card.is_active = False

            # Dodavanje nove kartice
            new_card = DriverCard(
                card_number=new_card_number,
                driver_id=driver.id,
                is_active=True,
                expiry_date=expiry_date
            )
            db.session.add(new_card)
            flash(_("Nova tahografska kartica je dodata."), "success")
        elif current_card and expiry_date:
            current_card.expiry_date = expiry_date
            flash(_("Datum važenja tahograf kartice je ažuriran."), "info")

        # CPC kartica
        driver.cpc_card_number = cpc_card_number
        driver.cpc_expiry_date = cpc_expiry_date

        db.session.commit()
        flash(_("Podaci o vozaču su uspešno ažurirani."), "success")
        return redirect(url_for('main.driver_detail', driver_id=driver.id))

    # GET zahtev - priprema podataka za prikaz u formi
    active_card = current_card
    expiry_date_str = active_card.expiry_date.strftime('%Y-%m-%d') if active_card and active_card.expiry_date else ''
    card_number = active_card.card_number if active_card else ''
    cpc_expiry_date_str = driver.cpc_expiry_date.strftime('%Y-%m-%d') if driver.cpc_expiry_date else ''

    return render_template(
        'update_driver.html',
        driver=driver,
        expiry_date_str=expiry_date_str,
        card_number=card_number,
        cpc_expiry_date_str=cpc_expiry_date_str,
        current_date=current_date
    )

@main.route('/terms')
def terms():
    # Ako je poslodavac prijavljen → detaljni uslovi
    if session.get('user_type') == 'employer' and session.get('user_id'):
        return render_template('terms.html')
    # Inače → javni uslovi
    return render_template('terms_public.html')


@main.route('/terms_public')
def terms_public():
    # Javna verzija uslova korišćenja, bez ograničenja pristupa
    return render_template('terms_public.html')

@main.route('/privacy-policy')
def privacy_policy():
    return render_template('privacy_policy.html')

@main.route('/employer/<int:employer_id>')
def employer_detail(employer_id):
    # ✅ Dozvoljen pristup samo ulogovanim poslodavcima
    if session.get('user_type') != 'employer' or not session.get('user_id'):
        flash(_("Morate biti prijavljeni kao poslodavac da biste videli ovu stranicu."), "warning")
        return redirect(url_for('main.login'))

    employer = Employer.query.get_or_404(employer_id)
    return render_template('employer_detail.html', employer=employer)


@main.route('/about')
def about():
    return render_template('about.html')

@main.route('/contact')
def contact():
    return render_template('contact.html')

@main.route('/set_language/<lang>')
def set_language(lang):
    if lang not in ['sr', 'en', 'de']:
        lang = 'sr'

    resp = redirect(request.referrer or url_for('main.index'))
    resp.set_cookie('lang', lang, max_age=30*24*60*60)  # 30 dana
    return resp


@main.route("/test_translation")
def test_translation():
    return _("Dobrodošli")