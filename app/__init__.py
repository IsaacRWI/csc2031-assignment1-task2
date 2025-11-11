from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from config import Config
from flask_wtf import CSRFProtect
from flask_bcrypt import Bcrypt

db = SQLAlchemy()
csrf = CSRFProtect()
bcrypt = Bcrypt()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    csrf.init_app(app)
    bcrypt.init_app(app)

    from .routes import main
    app.register_blueprint(main)

    return app