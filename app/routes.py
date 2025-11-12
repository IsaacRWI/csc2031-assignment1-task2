from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from app import login_manager, db
from app.forms import LoginForm,TOTPForm,SetUpMFAForm
from app.models import User
from flask_login import current_user, login_user, logout_user,login_required
from uuid import uuid4
import pyotp
import qrcode
import io
import base64

main = Blueprint('main', __name__)

@main.route('/', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            regenerate_session()
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('main.dashboard'))
        else:
            flash('Login Unsuccessful, username or password incorrect', "danger")
    return render_template('login.html', form=form)

@main.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@main.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.login'))

@main.route("/mfa_setup", method=["GET", "POST"])
@login_required
def mfa_setup():
    user = current_user
    if user.mfa_enabled:
        flash("MFA is already enabled on this account", "info")
        return redirect(url_for("main.dashboard"))
    if not user.totp_secret:
        user.totp_secret = pyotp.random_base32()
        db.session.commit()

    uri =user.get_totp_uri()
    qr = qrcode.make(uri)
    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode("ascii")

    form = SetUpMFAForm()
    if form.validate_on_submit():
        token = form.token.data
        if user.verify_totp(token):
            user.mfa_enabled = True
            db.session.commit()
            flash("MFA has been enabled for your account.", "info")
            return redirect(url_for('main.dashboard'))
        else:
            flash("Invalid authentication code. Try again.", "danger")

    return render_template('mfa_setup.html', form=form, qr_code=qr_b64, secret=user.totp_secret)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def regenerate_session():
    """had to ask ai for help with this function"""
    session.clear()
    session["csrf_token"] = uuid4().hex
    # print("session regenerate")