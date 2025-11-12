from . import db, bcrypt
from flask_login import UserMixin
import pyotp
from datetime import datetime, timezone

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    totp_secret = db.Column(db.String(16), nullable=False, default="")  # had to ask ai to help find this
    mfa_enabled = db.Column(db.Boolean, nullable=False, default=False)   # i forgot set default values for non-nullable fields
    attempts = db.Column(db.Integer, nullable=False, default=0)
    lockout_until = db.Column(db.DateTime, nullable=True)

    def hash_password(self, text_password):
        self.password = bcrypt.generate_password_hash(text_password).decode('utf-8')

    def check_password(self, text_password):
        # print("Stored hash:", self.password )
        return bcrypt.check_password_hash(self.password, text_password)

    def get_totp_uri(self):
        return pyotp.totp.TOTP(self.totp_secret).provisioning_uri(name=self.username, issuer_name="task2")

    def verify_totp(self, token):
        if not self.totp_secret:
            return False
        totp = pyotp.TOTP(self.totp_secret)
        return totp.verify(token)

    def is_locked(self):
        if self.lockout_until and self.lockout_until > datetime.now(timezone.utc):
            return True
        else: return False