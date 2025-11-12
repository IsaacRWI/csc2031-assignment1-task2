from flask import Blueprint, render_template, redirect, url_for, request, flash
from app import login_manager
from app.models import User

main = Blueprint('main', __name__)

@main.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and user.password == password:
            flash('Login successful!')
            return redirect(url_for('main.dashboard'))
        else:
            flash('Invalid username or password.')

    return render_template('login.html')

@main.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@main.route('/logout')
def logout():
    return redirect(url_for('main.login'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))