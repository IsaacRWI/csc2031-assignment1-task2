from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from config import Config
from flask_wtf import CSRFProtect
from flask_bcrypt import Bcrypt
from flask_login import LoginManager

# initialize flask extensions for later use
db = SQLAlchemy()
csrf = CSRFProtect()
bcrypt = Bcrypt()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    csrf.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)  # initialize

    login_manager.login_view = "main.login"
    login_manager.login_message_category = "info"

    from .routes import main
    app.register_blueprint(main)

    return app