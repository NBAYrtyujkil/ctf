# forms.py
from flask_wtf import FlaskForm
from wtforms import PasswordField, SubmitField
from wtforms.validators import DataRequired

class AdminLoginForm(FlaskForm):
    password = PasswordField('كلمة المرور', validators=[DataRequired()])
    submit = SubmitField('دخول')
