from app import create_app, db
from flask_wtf import CSRFProtect

app = create_app()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)