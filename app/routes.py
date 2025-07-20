from .utils import add_new_driver_card
from flask import Blueprint, render_template, request, session, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from app.models import Employer
from app import db
from app.helpers import konvertuj_tekst
from sqlalchemy import or_
import os
import hashlib
from app.utils import hash_jmbg

from sqlalchemy.orm import joinedload
from .models import Driver, Rating, Employer

from datetime import datetime

from .utils import generate_reset_token
from .utils import verify_reset_token

from .decorators import login_required, superadmin_required
from app.models import Driver, DriverCard

main = Blueprint('main', __name__)


def generate_salt():
    return os.urandom(16)

def hash_jmbg_with_salt(jmbg: str, salt: bytes) -> str:
    return hashlib.sha256(salt + jmbg.encode('utf-8')).hexdigest()



def add_new_driver_card(driver, new_card_number, expiry_date=None):
    # Деактивирај све претходне картице
    for card in driver.cards:
        card.is_active = False

    # Додај нову као активну
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
        flash("Морате бити пријављени као послодавац.")
        return redirect(url_for('main.login'))

    driver = Driver.query.get_or_404(driver_id)

    if request.method == 'POST':
        new_card_number = request.form.get('card_number', '').strip()
        issue_date_str = request.form.get('issue_date', '').strip()
        expiry_date_str = request.form.get('expiry_date', '').strip()

        # Проверa датума
        issue_date = None
        expiry_date = None

        if issue_date_str:
            try:
                issue_date = datetime.strptime(issue_date_str, '%Y-%m-%d').date()
            except ValueError:
                flash("Неисправан формат датума издавања.")
                return redirect(url_for('main.add_driver_card', driver_id=driver.id))

        if expiry_date_str:
            try:
                expiry_date = datetime.strptime(expiry_date_str, '%Y-%m-%d').date()
            except ValueError:
                flash("Неисправан формат датума истека.")
                return redirect(url_for('main.add_driver_card', driver_id=driver.id))

        # Проверa да ли картица већ постоји (јединствени број)
        existing_card = DriverCard.query.filter_by(card_number=new_card_number).first()
        if existing_card:
            flash("Ова картица већ постоји у систему.")
            return redirect(url_for('main.add_driver_card', driver_id=driver.id))

        # Додај нову картицу и деактивирај претходне
        add_new_driver_card(driver, new_card_number, issue_date, expiry_date)
        flash("Нова картица је успешно додата и активирана.")
        return redirect(url_for('main.driver_profile', driver_id=driver.id))  # или нека страница са детаљима возача

    return render_template('add_card.html', driver=driver)


# INDEX
@main.route('/')
def index():
    if 'user_id' in session:
        print(dict(session))
        user_type = session.get('user_type')
        if user_type == 'employer':
            return redirect(url_for('main.drivers'))
        elif user_type == 'superadmin':
            return redirect(url_for('main.admin_dashboard'))
    return render_template('index.html', current_lang=session.get('lang', 'sr'))



from datetime import datetime

from flask import flash, redirect, render_template, request, session, url_for
from datetime import datetime
from app import db
from app.models import Driver, DriverCard
from app.utils import generate_salt, hash_jmbg_with_salt

@main.route('/drivers/add', methods=['GET', 'POST'])
def add_driver():
    employer_id = session.get('user_id')
    if not employer_id:
        flash("Молимо пријавите се као послодавац.")
        return redirect(url_for('main.login'))

    if request.method == 'POST':
        full_name = request.form['full_name'].strip()
        jmbg = request.form['jmbg'].strip()

        # Проверa дужине JMBG
        if len(jmbg) != 13 or not jmbg.isdigit():
            flash("ЈМБГ мора садржати тачно 13 цифара.")
            return redirect(url_for('main.add_driver'))

        card_number = request.form.get('card_number', '').strip()
        issue_date_str = request.form.get('issue_date', '').strip()
        expiry_date_str = request.form.get('expiry_date', '').strip()
        cpc_card_number = request.form.get('cpc_card_number', '').strip()
        cpc_expiry_date_str = request.form.get('cpc_expiry_date', '').strip()

        if card_number and len(card_number) != 16:
            flash("Број тахограф картице мора имати тачно 16 карактера.")
            return redirect(url_for('main.add_driver'))

        issue_date = datetime.strptime(issue_date_str, '%Y-%m-%d').date() if issue_date_str else None
        expiry_date = datetime.strptime(expiry_date_str, '%Y-%m-%d').date() if expiry_date_str else None
        cpc_expiry_date = datetime.strptime(cpc_expiry_date_str, '%Y-%m-%d').date() if cpc_expiry_date_str else None

        # Тражи постојећег возача тако што пролази кроз све и упоређује hash
        existing_driver = None
        all_drivers = Driver.query.all()
        for driver in all_drivers:
            if hash_jmbg_with_salt(jmbg, driver.salt) == driver.jmbg_hashed:
                existing_driver = driver
                break

        if existing_driver:
            if existing_driver.active and existing_driver.employer_id == employer_id:
                flash("Возач већ ради код вас.")
                return redirect(url_for('main.drivers'))

            elif existing_driver.active and existing_driver.employer_id != employer_id:
                flash("Возач већ ради код другог послодавца.")
                return redirect(url_for('main.search_driver'))

            else:
                existing_driver.full_name = full_name
                existing_driver.employer_id = employer_id
                existing_driver.cpc_card_number = cpc_card_number or None
                existing_driver.cpc_expiry_date = cpc_expiry_date
                existing_driver.active = True
                db.session.commit()

                if card_number:
                    new_card = DriverCard(
                        card_number=card_number,
                        driver_id=existing_driver.id,
                        is_active=True,
                        issue_date=issue_date,
                        expiry_date=expiry_date
                    )
                    db.session.add(new_card)
                    db.session.commit()

                flash("Постојећи возач је преузет у вашу фирму.")
                return redirect(url_for('main.drivers'))

        # Додавање новог возача са новим salt-ом
        salt = generate_salt()
        jmbg_hashed = hash_jmbg_with_salt(jmbg, salt)

        new_driver = Driver(
            full_name=full_name,
            jmbg_hashed=jmbg_hashed,
            salt=salt,
            cpc_card_number=cpc_card_number or None,
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

        flash("Нови возач је успешно додат.")
        return redirect(url_for('main.drivers'))

    return render_template('add_driver.html', current_lang=session.get('lang', 'sr'))




@main.route('/drivers/search', methods=['GET', 'POST'])
def search_driver():
    employer_id = session.get('user_id')
    if not employer_id:
        flash("Морате бити пријављени као послодавац.")
        return redirect(url_for('main.login'))

    driver = None
    ratings_info = []
    show_additional_fields = False

    if request.method == 'POST':
        search_input = request.form.get('search_input', '').strip()
        print(f"🔍 Претрага за унетим: {search_input}")

        if search_input.isdigit() and len(search_input) == 13:
            from app.utils import hash_jmbg_with_salt  # увези функцију
            all_drivers = Driver.query.all()
            for d in all_drivers:
                hashed = hash_jmbg_with_salt(search_input, d.salt)
                if hashed == d.jmbg_hashed:
                    driver = d
                    break
            print(f"🔎 Пронађен возач: {driver}")
        else:
            card = DriverCard.query.filter_by(card_number=search_input).first()
            print(f"🔎 Пронађена картица: {card}")
            if card:
                driver = card.driver

        if not driver:
            flash("Возач са унетим подацима није пронађен.")
            show_additional_fields = True
        else:
            for r in driver.ratings:
                employer = Employer.query.get(r.employer_id)
                ratings_info.append({
                    'employer_name': employer.company_name if employer else "Непознат послодавац",
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
        flash('Немате дозволу за ову акцију.', 'danger')
        return redirect(url_for('main.login'))

    driver = Driver.query.get_or_404(driver_id)
    employer_id = session['user_id']

    if driver.employer_id == employer_id:
        if not driver.active:
            driver.active = True
            db.session.commit()
            flash('Возач је поново активиран у вашем систему.', 'success')
        else:
            flash('Возач је већ код вас и активан је.', 'info')
        return redirect(url_for('main.driver_detail', driver_id=driver.id))

    # Ако је возач активан код другог послодавца - НЕ ДОЗВОЉАВАМО преузимање
    if driver.active and driver.employer_id != employer_id:
        flash('Возач је већ активан код другог послодавца и не може се преузети.', 'warning')
        return redirect(url_for('main.driver_detail', driver_id=driver.id))

    # Возач није активан или нема послодавца, може се преузети
    driver.employer_id = employer_id
    driver.active = True
    db.session.commit()

    flash(f'Возач {driver.full_name} је успешно преузет у вашу фирму.', 'success')
    return redirect(url_for('main.driver_detail', driver_id=driver.id))




@main.route('/profile', methods=['GET', 'POST'])
def employer_profile():
    if session.get('user_type') != 'employer':
        flash("Немате приступ овој страници.")
        return redirect(url_for('main.index'))

    employer_id = session.get('user_id')
    employer = Employer.query.get_or_404(employer_id)

    if request.method == 'POST':
        employer.company_name = request.form['company_name']
        employer.email = request.form['email']

        new_password = request.form.get('password')
        if new_password:
            employer.password_hash = generate_password_hash(new_password)

        db.session.commit()
        flash("Подаци су успешно ажурирани.")
        return redirect(url_for('main.drivers'))

    return render_template('employer_profile.html', employer=employer, current_lang=session.get('lang', 'sr'))


@main.route('/drivers/<int:driver_id>/activate', methods=['POST'])
def activate_existing_driver(driver_id):
    employer_id = session.get('user_id')
    if not employer_id:
        flash("Молимо пријавите се.")
        return redirect(url_for('main.login'))

    driver = Driver.query.get_or_404(driver_id)

    # Ако је већ активан код другог послодавца → забрана
    if driver.active and driver.employer_id != employer_id:
        flash("Овај возач је тренутно запослен код другог послодавца и не можете га преузети.")
        return redirect(url_for('main.drivers'))

    # Ако је већ код овог послодавца → само осигурај да је активан
    if driver.employer_id == employer_id:
        driver.active = True
        db.session.commit()
        flash(f"Возач {driver.full_name} је сада активан код ваше фирме.")
        return redirect(url_for('main.drivers'))

    # Ако је неактиван → преузми и активирај
    driver.employer_id = employer_id
    driver.active = True
    db.session.commit()
    flash(f"Возач {driver.full_name} је успешно додат вашој фирми.")
    return redirect(url_for('main.drivers'))



# REGISTER
@main.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        company_name = request.form['company_name'].strip()
        pib = request.form['pib'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        password_hash = generate_password_hash(password)

        # Валидација PIB
        if not pib.isdigit() or len(pib) != 9:
            flash("PIB мора садржати тачно 9 цифара.")
            return redirect(url_for('main.register'))

        existing = Employer.query.filter_by(pib=pib).first()
        if existing:
            if not existing.active:
                flash("Фирма са овим PIB-ом није активна. Регистрација није могућа.")
                return redirect(url_for('main.register'))
            else:
                flash("Постоји већ налог са тим PIB-ом.")
                return redirect(url_for('main.register'))

        new_employer = Employer(
            company_name=company_name,
            pib=pib,
            email=email,
            password_hash=password_hash,
            active=True  # нова фирма је активна по дефаулту
        )
        db.session.add(new_employer)
        db.session.commit()
        flash("Успешна регистрација. Сада се можете пријавити.")
        return redirect(url_for('main.login'))

    return render_template('register.html', current_lang=session.get('lang', 'sr'))


@main.route('/logout')
def logout():
    session.clear()
    flash("Успешно сте се одјавили.")
    return redirect(url_for('main.index'))

@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        employer = Employer.query.filter_by(email=email).first()
        if employer and check_password_hash(employer.password_hash, password):

            # ✅ Провера да ли је фирма активна
            if not employer.active:
                flash("Ваша фирма није активна. Пријава није могућа.")
                return redirect(url_for('main.login'))

            session['user_id'] = employer.id
            session['user_type'] = 'superadmin' if employer.is_superadmin else 'employer'
            session['company_name'] = employer.company_name

            if employer.is_superadmin:
                return redirect(url_for('main.admin_dashboard'))
            else:
                return redirect(url_for('main.drivers'))

        flash("Погрешан емаил или лозинка.")
        return redirect(url_for('main.login'))

    return render_template('login.html', current_lang=session.get('lang', 'sr'))





from flask import session

@main.route('/dashboard')
def dashboard():
    # Узмемо company_name из сесије
    company_name = session.get('company_name')
    if not company_name:
        # Ако нема података у сесији, редирект на пријаву
        flash("Молимо пријавите се.")
        return redirect(url_for('main.login'))

    return render_template('dashboard.html', company_name=company_name, current_lang=session.get('lang', 'sr'))

    
from app.models import Driver

from sqlalchemy import func

@main.route('/drivers')
def drivers():
    employer_id = session.get('user_id')
    if not employer_id:
        flash("Молимо пријавите се.")
        return redirect(url_for('main.login'))

    employer = Employer.query.get(employer_id)
    if not employer:
        flash("Грешка при аутентикацији.")
        return redirect(url_for('main.login'))

    search = request.args.get('search', '').strip()

    # Сви активни возачи овог послодавца
    drivers_query = Driver.query.filter_by(employer_id=employer.id, active=True)

    if search:
        # Пошто JMBG више није доступан као отворени податак, НЕМОЖЕМО га претраживати
        # Уместо тога, претражујемо по:
        # - full_name
        # - broju тахограф картице (из повезаног модела DriverCard)
        # - броју CPC картице
        drivers_query = drivers_query.filter(
            or_(
                Driver.full_name.ilike(f'%{search}%'),
                Driver.cpc_card_number.ilike(f'%{search}%'),
                Driver.cards.any(DriverCard.card_number.ilike(f'%{search}%'))
            )
        )

    drivers_list = drivers_query.all()

    # Прорачун просечних оцена
    driver_ratings = {}
    for d in drivers_list:
        avg_rating = db.session.query(func.avg(Rating.stars)).filter(Rating.driver_id == d.id).scalar()
        driver_ratings[d.id] = round(avg_rating, 2) if avg_rating else None

    return render_template(
        'drivers.html',
        drivers=drivers_list,
        driver_ratings=driver_ratings,
        search=search,
        current_lang=session.get('lang', 'sr')
    )

@main.route('/drivers/search_card', methods=['GET', 'POST'])
def search_driver_by_card():
    company_name = session.get('company_name')
    if not company_name:
        flash("Молимо пријавите се.")
        return redirect(url_for('main.login'))

    employer = Employer.query.filter_by(company_name=company_name).first()
    if not employer:
        flash("Грешка при аутентикацији.")
        return redirect(url_for('main.login'))

    if request.method == 'POST':
        card_number = request.form['card_number'].strip()

        driver = Driver.query.filter_by(card_number=card_number).first()

        if not driver:
            flash("Возач са датим бројем тахограф картице не постоји.")
            return redirect(url_for('main.search_driver_by_card'))

        # Ако возач није тренутно код овог послодавца, прикажи му детаље где је све радио
        if driver.employer_id != employer.id:
            # Узми све послодавце код којих је возач радио (можда са другим таблама ако постоје)
            # Ако немаш историју послодаваца, можда мораш да додаш
            # За сада ћемо само приказати возача и поруку
            return render_template('driver_exists.html', driver=driver, employer=employer, current_lang=session.get('lang', 'sr'))

        # Ако је возач тренутно код овог послодавца - преусмери га на листу возача или детаље
        flash("Возач већ ради у вашој фирми.")
        return redirect(url_for('main.drivers'))

    return render_template('search_driver.html', current_lang=session.get('lang', 'sr'))


@main.route('/drivers/<int:driver_id>/exists', methods=['GET'])
def driver_exists(driver_id):
    employer_id = session.get('user_id')
    if not employer_id:
        flash("Молимо пријавите се.")
        return redirect(url_for('main.login'))

    driver = Driver.query.get_or_404(driver_id)

    # Узимање свих оцена и података о послодавцима код којих је возач радио
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


@main.route('/driver/<int:driver_id>/deactivate', methods=['POST'])
def deactivate_driver(driver_id):
    employer_id = session.get('user_id')
    if not employer_id or session.get('user_type') != 'employer':
        flash("Морате бити пријављени као послодавац.")
        return redirect(url_for('main.login'))

    driver = Driver.query.get_or_404(driver_id)
    if driver.employer_id != employer_id:
        flash("Немате дозволу да мењате статус овог возача.")
        return redirect(url_for('main.drivers'))

    driver.active = False
    db.session.commit()
    flash(f"Возач {driver.full_name} је сада неактиван.")
    return redirect(url_for('main.drivers'))



@main.route('/drivers/all')
def all_drivers():
    employer_id = session.get('user_id')
    if not employer_id:
        flash("Молимо пријавите се.")
        return redirect(url_for('main.login'))

    search = request.args.get('search')

    # Филтрирај све возаче који су радили код пријављеног послодавца, без обзира на статус
    drivers_query = Driver.query.filter_by(employer_id=employer_id)
    if search:
        drivers_query = drivers_query.filter(
            (Driver.full_name.ilike(f'%{search}%')) | 
            (Driver.card_number.ilike(f'%{search}%'))
        )

    drivers_list = drivers_query.all()

    # Израчунај просечну оцену за сваки возач
    from sqlalchemy import func
    driver_ratings = {}
    for d in drivers_list:
        avg_rating = db.session.query(func.avg(Rating.stars)).filter(Rating.driver_id == d.id).scalar()
        driver_ratings[d.id] = round(avg_rating, 2) if avg_rating else None

    return render_template('all_drivers.html', drivers=drivers_list, driver_ratings=driver_ratings, search=search, current_lang=session.get('lang', 'sr'))


# Ruta za prikaz forme za ocenjivanje vozaca
@main.route('/drivers/<int:driver_id>/rate', methods=['GET', 'POST'])
def rate_driver(driver_id):
    # Провера да ли је пријављен послодавац
    employer_id = session.get('user_id')
    if not employer_id:
        flash("Морате бити пријављени као послодавац да бисте оценили возача.")
        return redirect(url_for('main.login'))

    driver = Driver.query.get_or_404(driver_id)

    # Проверимо да ли већ постоји оцена овог возача од овог послодавца
    existing_rating = Rating.query.filter_by(driver_id=driver_id, employer_id=employer_id).first()

    if request.method == 'POST':
        rating_value = int(request.form['rating'])
        comment = request.form['comment']

        if existing_rating:
            # Ажурирај постојећу оцену
            existing_rating.stars = rating_value
            existing_rating.comment = comment
            existing_rating.created_at = datetime.utcnow()
            flash('Оцена је успешно ажурирана.')
        else:
            # Креирај нову оцену
            new_rating = Rating(
                driver_id=driver_id,
                employer_id=employer_id,
                stars=rating_value,
                comment=comment
            )
            db.session.add(new_rating)
            flash('Оцена је успешно додата.')

        db.session.commit()
        return redirect(url_for('main.drivers'))

    return render_template('rate_driver.html', driver=driver, existing_rating=existing_rating, current_lang=session.get('lang', 'sr'))

@main.route('/drivers/<int:driver_id>')
def driver_detail(driver_id):
    employer_id = session.get('user_id')
    if not employer_id:
        flash("Морате бити пријављени као послодавац.")
        return redirect(url_for('main.login'))

    driver = Driver.query.options(
        joinedload(Driver.cards),
        joinedload(Driver.ratings).joinedload(Rating.employer)
    ).get_or_404(driver_id)

    currently_employed_by_this_employer = (
        driver.active and driver.employer_id == employer_id
    )

    return render_template(
        'driver_detail.html',
        driver=driver,
        ratings=driver.ratings,
        can_update_driver=currently_employed_by_this_employer
    )


@main.route('/reset-password', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form['email']
        employer = Employer.query.filter_by(email=email).first()
        if employer:
            token = generate_reset_token(email)
            reset_url = url_for('main.reset_password_token', token=token, _external=True)
            
            # ✅ Замена flash линка слањем мејла
            send_reset_email(email, reset_url)
        
        # Увек враћамо исту поруку ради безбедности
        flash("Ако емаил постоји у систему, линк за ресет је послат.", 'info')
        return redirect(url_for('main.login'))

    return render_template('reset_password_request.html', current_lang=session.get('lang', 'sr'))


@main.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password_token(token):
    email = verify_reset_token(token)
    if not email:
        flash('Линк није валидан или је истекао.', 'danger')
        return redirect(url_for('main.login'))

    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form.get('confirm_password')

        # Проверa да ли се лозинке поклапају
        if new_password != confirm_password:
            flash("Лозинке се не поклапају.", "danger")
            return redirect(url_for('main.reset_password_token', token=token))

        employer = Employer.query.filter_by(email=email).first()
        if employer:
            employer.password_hash = generate_password_hash(new_password)
            db.session.commit()
            flash('Лозинка је успешно промењена.', 'success')
            return redirect(url_for('main.login'))

    return render_template('reset_password_form.html', token=token, current_lang=session.get('lang', 'sr'))



from flask_mail import Message
from app import mail  # из твоје апликације

def send_reset_email(to_email, reset_url):
    msg = Message("Ресетовање лозинке", recipients=[to_email])
    msg.body = f"""Здраво,

Затражили сте ресетовање лозинке. Кликните или налепите следећи линк у прегледач:

{reset_url}

Ако нисте Ви тражили ресет, слободно игноришите овај мејл.
"""
    mail.send(msg)


from flask_login import login_required, current_user

@main.route('/admin/firme')
@login_required
def sve_firme():
    if not current_user.is_superadmin:
        flash("Nemate pristup ovoj stranici.", "danger")
        return redirect(url_for('index'))

    from models import Employer  # ili kako ti je naziv modela za poslodavce
    sve_firme = Employer.query.all()
    return render_template('admin_firme.html', firme=sve_firme, current_lang=session.get('lang', 'sr'))


@main.route('/admin/dashboard')
def admin_dashboard():
    if session.get('user_type') != 'superadmin':
        flash("Немате приступ овој страници.")
        return redirect(url_for('main.login'))

    # Претрага фирми
    company_query = request.args.get('company_query', '').strip()
    pib_query = request.args.get('pib_query', '').strip()

    # Претрага возача
    driver_query = request.args.get('driver_query', '').strip()

    # Филтрирање фирми по имену и ПИБ-у
    employers = Employer.query
    if company_query:
        employers = employers.filter(Employer.company_name.ilike(f'%{company_query}%'))
    if pib_query:
        employers = employers.filter(Employer.pib.ilike(f'%{pib_query}%'))
    employers = employers.all()

    # Филтрирање возача по имену, тахограф картици (у DriverCard) и CPC броју
    drivers = Driver.query
    if driver_query:
        like_pattern = f'%{driver_query}%'
        # Правимо join са DriverCard табелом ради претраге по card_number
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
        flash("Немате приступ овој страници.")
        return redirect(url_for('main.login'))

    employer = Employer.query.get_or_404(employer_id)
    drivers = Driver.query.filter_by(employer_id=employer.id).all()

    return render_template('admin/employer_drivers.html', employer=employer, drivers=drivers, current_lang=session.get('lang', 'sr'))


@main.route('/change_language', methods=['POST'])
def change_language():
    lang = request.form.get('language', 'sr')          # 'sr', 'en', ...
    script = request.form.get('script', 'cyrillic')    # 'latin' или 'cyrillic', подразумевано ћирилица

    session['lang'] = lang
    session['script'] = script

    return redirect(request.referrer or url_for('main.index'))


@main.route('/admin/employer/<int:employer_id>/toggle_status')
def toggle_employer_status(employer_id):
    if session.get('user_type') != 'superadmin':
        flash("Немате приступ овој акцији.")
        return redirect(url_for('main.login'))

    employer = Employer.query.get_or_404(employer_id)
    employer.active = not employer.active
    db.session.commit()

    flash(f"Статус фирме '{employer.company_name}' је успешно промењен.")
    return redirect(url_for('main.admin_dashboard'))


from datetime import datetime

@main.route('/drivers/<int:driver_id>/update', methods=['GET', 'POST']) 
def update_driver(driver_id):
    employer_id = session.get('user_id')
    if not employer_id:
        flash("Морате бити пријављени као послодавац.", "danger")
        return redirect(url_for('main.login'))

    driver = Driver.query.get_or_404(driver_id)

    # ✅ Провери да ли је возач запослен код тренутног послодавца
    if not driver.active or driver.employer_id != employer_id:
        flash("Немате дозволу да ажурирате овог возача.", "danger")
        return redirect(url_for('main.driver_detail', driver_id=driver_id))

    if request.method == 'POST':
        # Прикупљање података из форме
        new_full_name = request.form.get('full_name', '').strip()
        new_card_number = request.form.get('card_number', '').strip()
        expiry_date_str = request.form.get('expiry_date', '').strip()
        cpc_card_number = request.form.get('cpc_card_number', '').strip()
        cpc_expiry_date_str = request.form.get('cpc_expiry_date', '').strip()

        # Конверзија датума
        expiry_date = None
        cpc_expiry_date = None

        if expiry_date_str:
            try:
                expiry_date = datetime.strptime(expiry_date_str, '%Y-%m-%d').date()
            except ValueError:
                flash("Неисправан формат датума истека.", "warning")
                return redirect(url_for('main.update_driver', driver_id=driver_id))

        if cpc_expiry_date_str:
            try:
                cpc_expiry_date = datetime.strptime(cpc_expiry_date_str, '%Y-%m-%d').date()
            except ValueError:
                flash("Неисправан формат истека CPC картице.", "warning")
                return redirect(url_for('main.update_driver', driver_id=driver_id))

        # Ажурирање имена ако је промењено
        if new_full_name and new_full_name != driver.full_name:
            driver.full_name = new_full_name

        # Пронађи тренутно активну картицу
        current_card = next((card for card in driver.cards if card.is_active), None)

        # Додај нову картицу ако је број промењен
        if new_card_number and (not current_card or current_card.card_number != new_card_number):
            if current_card:
                current_card.is_active = False

            new_card = DriverCard(
                card_number=new_card_number,
                driver_id=driver.id,
                is_active=True,
                expiry_date=expiry_date
            )
            db.session.add(new_card)
            flash("Додата је нова тахографска картица.", "success")
        else:
            flash("Број тахограф картице није промењен.", "info")

        # Ажурирај CPC податке
        driver.cpc_card_number = cpc_card_number or None
        driver.cpc_expiry_date = cpc_expiry_date

        db.session.commit()
        flash("Подаци о возачу су успешно ажурирани.", "success")
        return redirect(url_for('main.driver_detail', driver_id=driver.id))

    # ✅ За GET захтев — припреми датуми у облику 'YYYY-MM-DD' за шаблон
    active_card = next((card for card in driver.cards if card.is_active), None)
    expiry_date_str = active_card.expiry_date.strftime('%Y-%m-%d') if active_card and active_card.expiry_date else ''
    cpc_expiry_date_str = driver.cpc_expiry_date.strftime('%Y-%m-%d') if driver.cpc_expiry_date else ''

    return render_template(
        'update_driver.html',
        driver=driver,
        expiry_date_str=expiry_date_str,
        cpc_expiry_date_str=cpc_expiry_date_str
    )


@main.route('/terms')
def terms():
    # Ако је послодавац пријављен → детаљни услови
    if session.get('user_type') == 'employer' and session.get('user_id'):
        return render_template('terms.html')
    # Иначе → јавни услови
    return render_template('terms_public.html')


@main.route('/terms_public')
def terms_public():
    # Јавна верзија услова коришћења, без ограничења приступа
    return render_template('terms_public.html')

@main.route('/privacy-policy')
def privacy_policy():
    return render_template('privacy_policy.html')
