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
app.config['SECURITY_PASSWORD_SALT'] = 'salty'
SECRET_KEY = app.secret_key
bootstrap = Bootstrap(app)

DEBUG = True
TESTING = True
BCRYPT_LOG_ROUNDS = 13
WTF_CSRF_ENABLED = True
SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///db.sqlite')
SQLALCHEMY_TRACK_MODIFICATIONS = False

# Email Settings for Verification
mail_settings = {
    "MAIL_SERVER": 'smtp.gmail.com',
    "MAIL_PORT": 465,
    "MAIL_USE_TLS": False,
    "MAIL_USE_SSL": True,
    "MAIL_USERNAME": os.environ['EMAIL_USER'],
    "MAIL_PASSWORD": os.environ['EMAIL_PASSWORD']
}

app.config.update(mail_settings)
mail = Mail(app)
login_manager = LoginManager()
login_manager.init_app(app)
bcrypt = Bcrypt(app)
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


class Course(db.Model):
    __tablename__ = 'course'
    course_title = db.Column(db.String(64), primary_key=True)
    dept_id = db.Column(db.Integer, primary_key=True)
    sect_id = db.Column(db.Integer)
    instructor = db.Column(db.String(64))
    class_period = db.Column(db.String(64))


@login_manager.user_loader
def load_user(user_id):
    """User loader callback for Flask-Login."""
    return User.query.get(int(user_id))


class RegisterForm(FlaskForm):
    """Registration form."""
    username = StringField('Username', validators=[DataRequired(), Length(1, 64)])
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    password_again = PasswordField('Confirm Password',
                                   validators=[DataRequired(), EqualTo('password')])
    access = SelectField('Access', choices=[('STUDENT', 'STUDENT'), ('ROOT', 'ROOT'), ('ADMIN', 'ADMIN')])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class CourseForm(FlaskForm):
    course_title = StringField('Course Title', validators=[DataRequired()])
    dept_id = StringField('Department ID', validators=[DataRequired()])
    sect_id = StringField('Section ID', validators=[DataRequired()])
    instructor = StringField('Instructor', validators=[DataRequired()])
    class_period = StringField('Class Period', validators=[DataRequired()])
    submit = SubmitField('Add')


class ChangePasswordForm(FlaskForm):
    password = PasswordField(
        'password',
        # Password policy for SSP (just a min of 6 characters)
        validators=[DataRequired(), Length(min=6, max=25)]
    )
    confirm = PasswordField(
        'Confirm Password',
        validators=[
            DataRequired(),
            EqualTo('password', message='Passwords must match.')
        ]
    )


def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])


def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
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
        sender=app.config.get("MAIL_USERNAME")
    )
    mail.send(msg)


# Default route
@app.route('/', methods=['GET', 'POST'])
def login():
    page_template = 'base.html'
    form = LoginForm(request.form)
    if current_user.is_authenticated:
        # if user is logged in we get out of here
        return redirect(url_for('studentPlanner'))
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None or not user.verify_password(form.password.data):
            flash('Invalid username or password.')
            return redirect(url_for('login'))
        # log user in
        login_user(user)
        flash('You are now logged in!')
        if user.access == 'STUDENT':
            return redirect(url_for('studentPlanner'))
        elif user.access == 'ADMIN':
            return redirect(url_for('admin_course'))
        elif user.access == 'ROOT':
            return redirect(url_for('rootAuth'))

    return render_template(page_template, form=form)


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
        db.session.add(user)
        db.session.commit()
        token = generate_confirmation_token(user.email)
        confirm_url = url_for('confirm_email', token=token, _external=True)
        if user.access == 'STUDENT':
            html = render_template('activate.html', confirm_url=confirm_url)
            subject = "Please confirm your email"
            send_email(user.email, subject, html)
        elif user.access == 'STUDENT' or user.access == 'ROOT':
            html = render_template('activateRoot.html')
            subject = "Your privileged request has be received"
            send_email(user.email, subject, html)
        return redirect(url_for('login'))

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


@app.route('/rootcourse', methods=['GET', 'POST'])
def rootCourse():
    page_template = 'rootCourse.html'
    add_form = CourseForm(request.form)
    if add_form.validate_on_submit():
        course = Course(
            course_title=add_form.course_title.data,
            dept_id=add_form.dept_id.data,
            sect_id=add_form.sect_id.data,
            instructor=add_form.instructor.data,
            class_period=add_form.class_period.data
        )
        db.session.add(course)
        db.session.commit()

    return render_template(page_template, form=add_form)


@app.route('/rootsection')
def rootSection():
    page_template = 'rootSection.html'
    return render_template(page_template)


@app.route('/admincourse')
def admin_course():
    page_template = 'adminCourse.html'
    return render_template(page_template)


@app.route('/adminsection')
def admin_section():
    page_template = 'adminSection.html'
    return render_template(page_template)


@app.route('/studentplan')
def student_planner():
    page_template = 'studentPlanner.html'
    return render_template(page_template)


@app.route('/studentgen')
def student_generate():
    page_template = 'studentGenerate.html'
    return render_template(page_template)


@app.route('/studentcur')
def student_current():
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


#root/admin add catalog/course database
class Catalog(db.Model):
    __tablename__ = 'catalog'
    course_title = db.Column(db.String(64), primary_key=True)
    dept_id = db.Column(db.Integer, primary_key=True)
    course_id = db.Column(db.Integer)

  # catalog = Catalog(
  #  title=form.title.data,
  #  email=form.email.data,
  #  password=form.password.data,
   # access=form.access.data,
  #  confirmed=False
  #  )

  #  db.session.commit()