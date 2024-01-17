from datetime import datetime
from flask_login import UserMixin
from app.extensions import db
from werkzeug.security import generate_password_hash, check_password_hash
import time
import math
from collections import Counter

def shannon_entropy(password):
    n = len(password)
    char_frequencies = Counter(password)
    entropy = -sum((freq / n) * math.log2(freq / n) for freq in char_frequencies.values())
    return entropy

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    login_other_device_warning = db.Column(db.Boolean, default=False)
    ips = db.relationship('UserIP', backref='user', lazy=True)
    
    def init_password(self, password):
        self.password_hash = generate_password_hash(password)

    def set_password(self, password):
        # Check password length and complexity
        if (
            len(password) < 12 or
            not any(char.islower() for char in password) or
            not any(char.isupper() for char in password) or
            not any(char.isdigit() for char in password) or
            not any(char in "!@#$%^&*()-_+=<>?/" for char in password)
        ):
            raise ValueError("Password must be at least 12 characters long and include at least one uppercase letter, one lowercase letter, one digit, and one special character.")

        entropy = shannon_entropy(password)
        if entropy < 2.5:
            raise ValueError("Password has too low entropy, consider using more different characters")
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class UserIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(15), nullable=False)  
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_associated = db.Column(db.Boolean, default=False)

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    encrypted = db.Column(db.Boolean, default=False)
    public = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.Text, nullable=False)
    failed_login_requests = db.Column(db.Integer, nullable=False, default=0)
    last_request_date = db.Column(db.DateTime, default=datetime.utcnow)

