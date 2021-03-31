from flask import Flask, render_template, flash, request, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash, check_password_hash


import os
import datetime


# application instance
app = Flask(__name__)
app.secret_key = os.urandom(12)
bootstrap = Bootstrap(app)

SECURITY_PASSWORD_SALT = 'salty_salt_salt'
DEBUG = True
TESTING = True
BCRYPT_LOG_ROUNDS = 13
WTF_CSRF_ENABLED = True
SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///db.sqlite')
SQLALCHEMY_TRACK_MODIFICATIONS = False
MAIL_SERVER = 'smtp.googlemail.com'
MAIL_PORT = 465
MAIL_USE_TLS = False
MAIL_USE_SSL = True

# gmail authentication
MAIL_USERNAME = os.environ['APP_MAIL_USERNAME']
MAIL_PASSWORD = os.environ['APP_MAIL_PASSWORD']

# mail accounts
MAIL_DEFAULT_SENDER = '3codeeteers@gmail.com'
lm = LoginManager()
bcrypt = Bcrypt(app)
mail = Mail(app)
db = SQLAlchemy(app)


class User(UserMixin, db.Model):
    """User model."""
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True)
    email = db.Column(db.String(64))
    access = db.Column(db.String(64))
    password_hash = db.Column(db.String(128))
    confirmed = db.Column(db.Boolean, default=False)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)


@lm.user_loader
def load_user(user_id):
    """User loader callback for Flask-Login."""
    return User.query.get(int(user_id))


class RegisterForm(FlaskForm):
    """Registration form."""
    username = StringField('Username', validators=[DataRequired(), Length(1, 64)])
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    password_again = PasswordField('Password again',
                                   validators=[DataRequired(), EqualTo('password')])
    access = SelectField('Access', choices=[('STUDENT', 'STUDENT'), ('ROOT', 'ROOT'), ('ADMIN', 'ADMIN')])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    username = StringField('username', validators=[DataRequired()])
    password = PasswordField('password', validators=[DataRequired()])


class ChangePasswordForm(FlaskForm):
    password = PasswordField(
        'password',
        # Password policy for SSP (just a min of 6 characters)
        validators=[DataRequired(), Length(min=6, max=25)]
    )
    confirm = PasswordField(
        'Repeat password',
        validators=[
            DataRequired(),
            EqualTo('password', message='Passwords must match.')
        ]
    )


def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config[app.secret_key])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])


def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config[app.secret_key])
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
    except:
        return False
    return email


def send_email(to, subject, template):
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender=app.config['MAIL_DEFAULT_SENDER']
    )
    mail.send(msg)


# Default route
@app.route('/')
def login():
    page_template = 'base.html'
    return render_template(page_template)


@app.route('/register', methods=['GET', 'POST'])
def register():
    page_template = 'registration.html'
    form = RegisterForm(request.form)
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is not None:
            flash('Username already exists.')
            return redirect(url_for('register'))
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None:
            flash('Email already exists.')
            return redirect(url_for('register'))
        user = User(
            username=form.username.data,
            email=form.email.data,
            password=form.password.data,
            access=form.access.data,
            confirmed=False
        )
        print(user)
        db.session.add(user)
        db.session.commit()
        token = generate_confirmation_token(user.email)
        confirm_url = url_for('confirm_email', token=token, _external=True)
        html = render_template('activate.html', confirm_url=confirm_url)
        subject = "Please confirm your email"
        send_email(user.email, subject, html)
        print(token)
        print(confirm_url)
        print(send_email)
        return redirect(url_for('login'))
    else:
        print("No Validation")

    return render_template(page_template, form=form)


@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = confirm_token(token)
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
    user = User.query.filter_by(email=email).first_or_404()
    if user.confirmed:
        flash('Account already confirmed. Please login.', 'success')
    else:
        user.confirmed = True
        user.confirmed_on = datetime.datetime.now()
        db.session.add(user)
        db.session.commit()
        flash('You have confirmed your account. Thanks!', 'success')
    return redirect(url_for('login'))


@app.route('/root')
def rootAuth():
    page_template = 'rootAuth.html'
    return render_template(page_template)


@app.route('/rootcourse')
def rootCourse():
    page_template = 'rootCourse.html'
    return render_template(page_template)


@app.route('/rootsection')
def rootSection():
    page_template = 'rootSection.html'
    return render_template(page_template)


@app.route('/admincourse')
def adminCourse():
    page_template = 'adminCourse.html'
    return render_template(page_template)


@app.route('/adminsection')
def adminSection():
    page_template = 'adminSection.html'
    return render_template(page_template)


@app.route('/studentplan')
def studentPlanner():
    page_template = 'studentPlanner.html'
    return render_template(page_template)


@app.route('/studentgen')
def studentGenerate():
    page_template = 'studentGenerate.html'
    return render_template(page_template)


@app.route('/studentcur')
def studentCurrent():
    page_template = 'studentCurrent.html'
    return render_template(page_template)


@app.errorhandler(404)
def page_not_found_error(error):
    page_template = '404.html'
    return render_template(page_template, error=error)


@app.errorhandler(500)
def internal_server_error(error):
    page_template = '500.html'
    return render_template(page_template, error=error)


# Create database if does not exist
db.create_all()


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=4000)

