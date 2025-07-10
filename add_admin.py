from app import create_app, db
from app.models import Employer

app = create_app()

with app.app_context():
    admin = Employer.query.filter_by(email="lazici19@gmail.com").first()
  # или изабери конкретног по емаилу
    if admin:
        admin.is_superadmin = True
        db.session.commit()
        print("✅ Nalog je postao superadmin.")
    else:
        print("❌ Nema nijednog poslodavca u bazi.")
