from app import db
from datetime import datetime
from flask_login import UserMixin
import hashlib


class Driver(db.Model):
    __tablename__ = 'driver'

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    jmbg_hashed = db.Column(db.String(64), unique=True, nullable=False)
    salt = db.Column(db.LargeBinary(16), nullable=False)  # Додајемо salt као бинарни низ

    cpc_card_number = db.Column(db.String(32), unique=True, nullable=True)
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
    stars = db.Column(db.Integer, nullable=False)  # Оцена од 1 до 5
    comment = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    employer_id = db.Column(db.Integer, db.ForeignKey('employer.id'), nullable=False)
    driver_id = db.Column(db.Integer, db.ForeignKey('driver.id'), nullable=False)

    driver = db.relationship('Driver', back_populates='ratings')
    employer = db.relationship('Employer', back_populates='ratings')
