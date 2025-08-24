from app import db
from datetime import datetime
from flask_login import UserMixin
import hashlib

class Employer(db.Model, UserMixin):
    __tablename__ = 'employer'  # eksplicitno
    id = db.Column(db.Integer, primary_key=True)
    company_name = db.Column(db.String(100), nullable=False)
    pib = db.Column(db.String(9), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    phone_number = db.Column(db.String(20), nullable=True)
    is_superadmin = db.Column(db.Boolean, default=False)
    active = db.Column(db.Boolean, default=True, nullable=False)

    drivers = db.relationship('Driver', back_populates='employer', lazy=True)
    ratings = db.relationship('Rating', back_populates='employer', lazy=True)

class Driver(db.Model):
    __tablename__ = 'driver'

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    jmbg_hashed = db.Column(db.String(64), unique=True, index=True, nullable=False)
    salt = db.Column(db.LargeBinary(16), nullable=False)  # Dodajemo salt kao binarni niz

    cpc_card_number = db.Column(db.String(9), unique=True, nullable=False)
    cpc_expiry_date = db.Column(db.Date, nullable=True)

    active = db.Column(db.Boolean, default=True)
    employer_id = db.Column(db.Integer, db.ForeignKey('employer.id'))

    employer = db.relationship("Employer", back_populates="drivers")
    ratings = db.relationship('Rating', back_populates='driver', lazy=True)
    cards = db.relationship(
        'DriverCard',
        back_populates='driver',
        lazy='joined',
        order_by='desc(DriverCard.issue_date)'
    )

class DriverCard(db.Model):
    __tablename__ = 'driver_cards'
    id = db.Column(db.Integer, primary_key=True)
    card_number = db.Column(db.String(20), unique=True, nullable=False)
    driver_id = db.Column(db.Integer, db.ForeignKey('driver.id'), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    issue_date = db.Column(db.Date, nullable=True)
    expiry_date = db.Column(db.Date, nullable=True)

    driver = db.relationship('Driver', back_populates='cards')


class Rating(db.Model):
    __tablename__ = 'rating'
    id = db.Column(db.Integer, primary_key=True)
    stars = db.Column(db.Integer, nullable=False)  # Ocena od 1 do 5
    comment = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    employer_id = db.Column(db.Integer, db.ForeignKey('employer.id'), nullable=False)
    driver_id = db.Column(db.Integer, db.ForeignKey('driver.id'), nullable=False)

    driver = db.relationship('Driver', back_populates='ratings')
    employer = db.relationship('Employer', back_populates='ratings')
