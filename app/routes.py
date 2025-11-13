from flask import Blueprint, render_template, redirect, url_for, request, flash, session, abort, send_file
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
from captcha.image import ImageCaptcha
import random
import string
import logging

logging.basicConfig(filename="app.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")  # sets up logging

def log_event(level, message, username=None):
    """function to define logging message format and log tags"""
    ip = request.remote_addr
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"{timestamp} Client IP:{ip}, User:{username or "N/A"} | {message}"
    if level == "info":
        logging.info(log_message)
    elif level == "warning":
        logging.warning(log_message)

ip_attempts = defaultdict(list)

def remove_old_attempts(attempts, window_sec=60):
    """function to remove login attempts older than 1 minute for 7 login attempts in 1 minute lockout"""
    now = time.time()
    return [i for i in attempts if now - i < window_sec]

def random_text(length=5):
    """function to generate random text to turn into captcha images later"""
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=length))

main = Blueprint('main', __name__)

@main.route('/', methods=['GET', 'POST'])
def login():
    ip = request.remote_addr  # gets the clients ip for logging
    form = LoginForm()
    ip_attempts[ip] = remove_old_attempts(ip_attempts[ip])  # remove old login attempts older than 1 minute

    if len(ip_attempts[ip]) >= 6:  # if 7 login attempts in 1 minute
        flash("Too many login attempts from this IP address. Please try again later.", "danger")  # flash warning message
        log_event("warning", "account lockout for 7 failed login attempts in 1 minute", form.username.data)  # log account lock out
        return render_template('login.html', form=form, require_captcha=False)  # return to login page

    if current_user.is_authenticated:  # if user is already logged in
        return redirect(url_for('main.dashboard'))  # this bit i had to ask ai why it wasnt working and this was one of the solutions it suggested

    user = User.query.filter_by(username=form.username.data).first() if form.username.data else None  # is username is not empty and is in database then set user to that username

    is_locked = user.is_locked() if user else False  # variable for checking if the user is locked out  if you dont use a variable the ide gets mad and makes everything red

    if is_locked:  # in event of an account lock out
        # print("still locked")
        require_captcha = False
        lockout_dt = user.lockout_until  # had to ask ai for help with fixing this part too
        if lockout_dt.tzinfo is None:
            lockout_dt = lockout_dt.replace(tzinfo=timezone.utc)  # converts the lockout time from naive to utc time for comparison
        time_left = lockout_dt - datetime.now(timezone.utc)
        minutes, seconds = divmod(time_left.seconds, 60)
        flash(f'Account timed out, try again in {minutes}m {seconds}s.', 'danger')
        ip_attempts[ip].append(time.time())  # increment the ip based attempts by 1
        # print("ip attempts append")
        return render_template('login.html', form=form, require_captcha=require_captcha)
    else:  # not locked out
        require_captcha = user and 2 <= user.attempts < 4  # if user is in database and user-based attempts is between 2 and 4

    if require_captcha and "captcha_text" not in session:  # if captcha is required and no captcha text is generated yet
        session["captcha_text"] = random_text()  # generate random text for captcha
        log_event("info", "captcha triggered", form.username.data)
        log_event("warning", "suspicious login pattern", form.username.data)

    if form.validate_on_submit():  # just means both fields werent empty
        ip_attempts[ip].append(time.time())  # increment the ip based attempts by 1
        # print("ip attempts append")
        if user:
            if require_captcha:
                user_captcha = (form.captcha.data or "").strip().upper()  # user input for the captcha
                actual_captcha = session.get('captcha_text', '').upper()  # captcha text generated earlier
                if user_captcha != actual_captcha:  # wrong captcha
                    flash("Wrong captcha, try again", "danger")
                    log_event("warning", "failed captcha attempt", form.username.data)
                    user.attempts += 1  # increment account based attempts by 1
                    db.session.commit()
                    # print("failed captcha", user.attempts)
                    session['captcha_text'] = random_text()  # regenerate captcha text
                    return render_template('login.html', form=form, require_captcha=require_captcha)
            session.pop('captcha_text', None)

        if user.check_password(form.password.data):  # hashed input matches stored hash through bcrypt with salt  the salt thing didnt want to work for some time
            log_event("info", "pre mfa login successful", form.username.data)
            user.attempts = 0  # reset account based attempts to 0
            user.lockout_until = None  # reset account lockout time
            db.session.commit()
            if user.mfa_enabled:  # if mfa is already set up
                session["pre_mfa_user_id"] = user.id  # for the mfa verification page to know which user you are trying to log in as
                return redirect(url_for("main.mfa_verify"))  # redirect to verification page
            else:  # account has not set up mfa yet
                session["pre_mfa_user_id"] = user.id
                return redirect(url_for("main.mfa_setup"))
        else:  # hashed input does not match store hash
            user.attempts += 1  # increment account based attempts by 1
            # print("failed + 1", user.attempts)
            db.session.commit()
            log_event("warning", "failed login attempt", form.username.data)

            if user.attempts >= 4:  # if you failed login 4 times in a row (its actually 5 attempts here because of the logic)
                # print("5 fails locked")
                log_event("warning", "account lockout 5 consecutive failed login attempts", form.username.data)
                user.lockout_until = datetime.now(timezone.utc) + timedelta(minutes=5)  # lock out account for 5 minutes
                user.attempts = 0  # reset account based attempts to 0
                db.session.commit()
                flash("Account locked for 5 minutes due to too many failed attempts, please try again later.", "danger")
                return render_template('login.html', form=form, require_captcha=False)
            else:
                flash('Login Unsuccessful, username or password incorrect', "danger")
    return render_template('login.html', form=form, require_captcha=require_captcha,)

@main.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@main.route('/logout')
@login_required
def logout():
    log_event("info", "logout", current_user.username)
    session.clear()  # clears session data
    logout_user()
    return redirect(url_for('main.login'))

@main.route("/mfa_setup", methods=["GET", "POST"])
def mfa_setup():
    """function for page to set up mfa"""
    if "pre_mfa_user_id" not in session:
        return redirect(url_for("main.login"))

    user = User.query.get(session["pre_mfa_user_id"])  # had to ask ai for help with this bit again
    if not user:  # cant find user in database
        flash("User not found, please try again.", "danger")
        log_event("warning", "failed mfa setup, user not found", user.username)
        return redirect(url_for("main.login"))

    if user.mfa_enabled:
        flash("MFA is already enabled on this account", "info")
        return redirect(url_for("main.dashboard"))
    if not user.totp_secret:
        user.totp_secret = pyotp.random_base32()
        db.session.commit()

    uri =user.get_totp_uri()  # pyotp to generate totp uri
    qr = qrcode.make(uri)  # turn that uri into a qr code
    buf = io.BytesIO()  # buffer to store the qr code
    qr.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode("ascii")

    form = SetUpMFAForm()
    if form.validate_on_submit():
        token = form.token.data  # user input for the totp code
        if user.verify_totp(token):  # if totp code matches
            user.mfa_enabled = True
            db.session.commit()
            flash("MFA has been enabled for your account.", "success")
            regenerate_session()
            login_user(user)
            flash("Login Successful, MFA setup and Verification Complete.", "success")
            log_event("info", "mfa successfully set up and authenticated, login successful", user.username)
            return redirect(url_for('main.dashboard'))
        else:
            flash("Invalid authentication code. Try again.", "danger")
            log_event("warning", "failed mfa authentication during set up, invalid TOTP code", user.username)

    return render_template('mfa_setup.html', form=form, qr_code=qr_b64, secret=user.totp_secret)

@main.route("/mfa_verify", methods=["GET", "POST"])
def mfa_verify():
    """function to verify accounts who already have mfa set up"""
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
            session.pop("pre_mfa_user_id", None)  # asked ai this needs a default value as well or it breaks
            flash("Login Successful, MFA Verification Complete.", "success")
            log_event("info", "mfa successfully authenticated, login successful", user.username)
            next_page= request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('main.dashboard'))
        else:
            flash("Invalid authentication code. Try again.", "danger")
            log_event("warning", "failed mfa authentication, invalid TOTP code", user.username)
    return render_template('mfa_verify.html', form=form)

@main.route("/captcha_image")
def captcha_image():
    image = ImageCaptcha(width=280, height=90)
    data = image.generate(session["captcha_text"])
    return send_file(data, mimetype='image/png')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def regenerate_session():
    """function to clear the session and regenerate a new csrf token"""
    session.clear()
    session["csrf_token"] = uuid4().hex
    # print("session regenerate")