from flask import Blueprint, render_template, redirect, url_for, request, flash, session, abort
from app import login_manager, db
from app.forms import LoginForm,TOTPForm,SetUpMFAForm
from app.models import User
from flask_login import current_user, login_user, logout_user,login_required
from uuid import uuid4
import pyotp
import qrcode
import io
import base64
from collections import defaultdict
import time
from datetime import datetime, timezone, timedelta

ip_attempts = defaultdict(list)

def remove_old_attempts(attempts, window_sec=60):
    now = time.time()
    return [i for i in attempts if now - i < window_sec]


main = Blueprint('main', __name__)

@main.route('/', methods=['GET', 'POST'])
def login():
    ip = request.remote_addr
    form = LoginForm()

    if len(ip_attempts[ip]) >= 7:
        flash("Too many login attempts from this IP address. Please try again later.", "danger")
        return render_template('login.html', form=form)

    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    if form.validate_on_submit():
        ip_attempts[ip].append(time.time())
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if user.is_locked():
                print("still locked")
                lockout_dt = user.lockout_until  # had to ask ai for help with fixing this part too
                if lockout_dt.tzinfo is None:
                    lockout_dt = lockout_dt.replace(tzinfo=timezone.utc)
                time_left = lockout_dt - datetime.now(timezone.utc)
                minutes, seconds = divmod(time_left.seconds, 60)
                flash(f'Account timed out, try again in {minutes}m {seconds}s.', 'danger')
                return render_template('login.html', form=form)

        if user.check_password(form.password.data):
            user.attempts = 0
            user.lockout_until = None
            db.session.commit()
            if user.mfa_enabled:
                session["pre_mfa_user_id"] = user.id
                return redirect(url_for("main.mfa_verify"))
            else:
                session["pre_mfa_user_id"] = user.id
                return redirect(url_for("main.mfa_setup"))
        else:
            user.attempts += 1
            print("failed + 1", user.attempts)
            db.session.commit()

            if user.attempts >= 5:
                print("5 fails locked")
                user.lockout_until = datetime.now(timezone.utc) + timedelta(minutes=5)
                user.attempts = 0
                db.session.commit()
                flash("Account locked for 5 minutes due to too many failed attempts, please try again later.", "danger")
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

@main.route("/mfa_setup", methods=["GET", "POST"])
def mfa_setup():
    if "pre_mfa_user_id" not in session:
        return redirect(url_for("main.login"))

    user = User.query.get(session["pre_mfa_user_id"])
    if not user:
        flash("User not found, please try again.", "danger")
        return redirect(url_for("main.login"))

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
            flash("MFA has been enabled for your account.", "success")
            regenerate_session()
            login_user(user)
            flash("Login Successful, MFA setup and Verification Complete.", "success")
            return redirect(url_for('main.dashboard'))
        else:
            flash("Invalid authentication code. Try again.", "danger")

    return render_template('mfa_setup.html', form=form, qr_code=qr_b64, secret=user.totp_secret)

@main.route("/mfa_verify", methods=["GET", "POST"])
def mfa_verify():
    if "pre_mfa_user_id" not in session:
        return redirect(url_for("main.login"))

    user = User.query.get(session["pre_mfa_user_id"])
    if not user:
        flash("User not found, please try again.", "danger")
        return redirect(url_for("main.login"))

    form =TOTPForm()
    if form.validate_on_submit():
        token = form.token.data
        if user.verify_totp(token):
            regenerate_session()  # moved session regeneration before logging user in to fix bug where users would be stuck on login screen even after authentication
            login_user(user)
            session.pop("pre_mfa_user_id", None)  # asked ai this needs a default value as well
            flash("Login Successful, MFA Verification Complete.", "success")
            next_page= request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('main.dashboard'))
        else:
            flash("Invalid authentication code. Try again.", "danger")
    return render_template('mfa_verify.html', form=form)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def regenerate_session():
    """had to ask ai for help with this function"""
    session.clear()
    session["csrf_token"] = uuid4().hex
    # print("session regenerate")