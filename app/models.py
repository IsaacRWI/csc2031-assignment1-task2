from . import db
from flask_login import UserMixin
from flask_bcrypt import bcrypt

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

    def hash_password(self, text_password):
        self.password = bcrypt.generate_password_hash(text_password).decode('utf-8')

    def check_password(self, text_password):
        return bcrypt.check_password_hash(self.password, text_password)