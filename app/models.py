from . import db, bcrypt
from flask_login import UserMixin
import pyotp
from datetime import datetime, timezone

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    totp_secret = db.Column(db.String(16), nullable=False, default="")  # had to use ai to find this bug
    mfa_enabled = db.Column(db.Boolean, nullable=False, default=False)   # turns out you need a default value for non-nullable variables or the ide gets mad
    attempts = db.Column(db.Integer, nullable=False, default=0)  # attempt variable for counting login attempts for triggering captcha and the 5 minute lockout
    lockout_until = db.Column(db.DateTime(timezone=True), nullable=True)  # variable to keep track of when the lock out ends

    def hash_password(self, text_password):
        """function to hash the passwords through bcrypt"""
        self.password = bcrypt.generate_password_hash(text_password).decode('utf-8')

    def check_password(self, text_password):
        """function to check if the hashed input matches the stored hash through bcrypt"""
        # print("Stored hash:", self.password )
        return bcrypt.check_password_hash(self.password, text_password)

    def get_totp_uri(self):
        """function to generate totp uri through pyotp library"""
        return pyotp.totp.TOTP(self.totp_secret).provisioning_uri(name=self.username, issuer_name="task2")

    def verify_totp(self, token):
        """function to verify the totp code"""
        if not self.totp_secret:
            return False
        totp = pyotp.TOTP(self.totp_secret)
        return totp.verify(token)

    def is_locked(self):
        """
        had to ask ai how to fix this bit cant compare offset-naive and offset-aware datetimes just type error things
        simple function to check if the user is locked out
        """
        if self.lockout_until:
            lockout_dt = self.lockout_until
            # If naive, make it aware as UTC
            if lockout_dt.tzinfo is None:
                lockout_dt = lockout_dt.replace(tzinfo=timezone.utc)
            if lockout_dt > datetime.now(timezone.utc):
                return True
        return False