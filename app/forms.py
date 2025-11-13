from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, length

class LoginForm(FlaskForm):
    """login form to take advantage of wtforms built in csrf tokens with form.hidden_tag()"""
    username = StringField('username', validators=[DataRequired()])
    password = PasswordField('password', validators=[DataRequired()])
    captcha = StringField('captcha')
    submit = SubmitField('login')

# had to ask ai for pointers on how to do this
class TOTPForm(FlaskForm):
    token = StringField('authentication code', validators=[DataRequired(), length(min=6, max=6)])
    submit = SubmitField('verify')

class SetUpMFAForm(FlaskForm):
    token = StringField('authentication code', validators=[DataRequired(), length(min=6, max=6)])
    submit = SubmitField('enable mfa')