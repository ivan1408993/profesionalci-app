from app import create_app, db
from app.models import Employer

app = create_app()

with app.app_context():
    admin = Employer.query.filter_by(email="lazici19@gmail.com").first()
    if admin:
        admin.is_superadmin = False   # uklanja status superadmina
        db.session.commit()
        print("🚫 Nalog više nije superadmin.")
    else:
        print("❌ Nema nijednog poslodavca u bazi sa tim mejlom.")
