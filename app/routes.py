from flask import Blueprint, render_template, redirect, url_for, request, flash
from app import login_manager
from app.forms import LoginForm
from app.models import User
from flask_login import current_user, login_user, logout_user,login_required

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
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('main.dashboard'))
        else:
            flash('Login Unsuccessful', "danger")
    return render_template('login.html', form=form)

@main.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@main.route('/logout')
def logout():
    return redirect(url_for('main.login'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))