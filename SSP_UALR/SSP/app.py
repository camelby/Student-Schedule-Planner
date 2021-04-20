# Library Imports
from flask import Flask, render_template, flash, request, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from flask_mail import Mail, Message
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash, check_password_hash

import os
import datetime
import pandas as pd


# Set application instance
app = Flask(__name__)
app.secret_key = os.urandom(12)
app.config['SECURITY_PASSWORD_SALT'] = 'salty'
bootstrap = Bootstrap(app)


# Enable Cross-Site Request Forgery token validation
app.config['WTF_CSRF_ENABLED'] = True

# Set application configuration for database
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///db.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Set CSV file upload folder
UPLOAD_FOLDER = os.path.join(app.root_path, 'files')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Email settings for verification
mail_settings = {
    "MAIL_SERVER": 'smtp.gmail.com',
    "MAIL_PORT": 465,
    "MAIL_USE_TLS": False,
    "MAIL_USE_SSL": True,
    "MAIL_USERNAME": os.environ['EMAIL_USER'],
    "MAIL_PASSWORD": os.environ['EMAIL_PASSWORD']
}

# Set application configurations
app.config.update(mail_settings)
mail = Mail(app)
login_manager = LoginManager()
login_manager.init_app(app)
db = SQLAlchemy(app)


# User database model
class User(UserMixin, db.Model):
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

    # Definitions for password hashes for database storage and verification
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)


# Student planner database model(s)
class AddClass(db.Model):
    __tablename__ = 'add_class'
    user_id = db.Column(db.String(64), db.ForeignKey('users.id'), primary_key=True)
    course_title = db.Column(db.String(64))
    course_id = db.Column(db.Integer)
    dept_id = db.Column(db.String(64))
    sect_id = db.Column(db.String(64))
    instructor = db.Column(db.String(64))
    class_period = db.Column(db.String(64))


class Break(db.Model):
    __tablename__ = 'break'
    user_id = db.Column(db.String(64), db.ForeignKey('users.id'), primary_key=True)
    break_name = db.Column(db.String(64))
    break_period = db.Column(db.String(64))


class FinalSchedule(db.Model):
    __tablenamme__ = 'final_schedule'
    user_id = db.Column(db.String(64), db.ForeignKey('users.id'), primary_key=True)
    course_title = db.Column(db.String(64))
    course_id = db.Column(db.Integer)
    dept_id = db.Column(db.String(64))
    sect_id = db.Column(db.String(64))
    instructor = db.Column(db.String(64))
    class_period = db.Column(db.String(64))


# Course database model(s)
class Section(db.Model):
    __tablename__ = 'section'
    row_id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    course_title = db.Column(db.String(64))
    course_id = db.Column(db.Integer)
    dept_id = db.Column(db.String(64))
    sect_id = db.Column(db.String(64))
    instructor = db.Column(db.String(64))
    class_period = db.Column(db.String(64))


class Course(db.Model):
    __tablename__ = 'course'
    course_title = db.Column(db.String(64))
    dept_id = db.Column(db.String(64))
    course_id = db.Column(db.Integer, primary_key=True)


# User loader callback for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# WTF flask forms
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(1, 64)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    password_again = PasswordField('Confirm Password',
                                   validators=[DataRequired(), EqualTo('password')])
    access = SelectField('Access', choices=[('STUDENT', 'STUDENT'), ('ROOT', 'ROOT'), ('ADMIN', 'ADMIN')])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class SectionForm(FlaskForm):
    course_title = StringField('Course Title', validators=[DataRequired()])
    course_id = StringField('Course ID', validators=[DataRequired()])
    dept_id = StringField('Department ID', validators=[DataRequired()])
    sect_id = StringField('Section ID', validators=[DataRequired()])
    instructor = StringField('Instructor', validators=[DataRequired()])
    class_period = StringField('Class Period -- MWF or TR HH.MM - HH.MM (UTC)', validators=[DataRequired()])
    submit = SubmitField('Add')


class CourseForm(FlaskForm):
    course_title = StringField('Course Title', validators=[DataRequired()])
    dept_id = StringField('Department ID', validators=[DataRequired()])
    course_id = StringField('Course ID', validators=[DataRequired()])
    submit = SubmitField('Add')


class SearchForm(FlaskForm):
    choices = [('Course', 'Department', 'Instructor')]
    select = SelectField('Choose Search Filter:', choices=choices)
    search = StringField('')


class BreakForm(FlaskForm):
    break_name = StringField('Break Name', validators=[DataRequired()])
    break_period = StringField('Break Period', validators=[DataRequired()])
    submit = SubmitField('Add')


# TODO OPTIONAL: Implement password recovery
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


# Create confirmation token
def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.secret_key)
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])


# Set token for email confirmation and mark max age for one hour
def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.secret_key)
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
    except token.DoesNotExist:
        return False
    return email


# Email message template
def send_email(to, subject, template):
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender=app.config.get("MAIL_USERNAME")
    )
    mail.send(msg)


# Parse CSV file on upload
def parseCSV(file_path):
    # CVS column names
    col_names = ['course_title', 'course_id', 'dept_id', 'sect_id', 'instructor', 'class_period']
    # Use Pandas to parse the CSV file
    csv_data = pd.read_csv(file_path, names=col_names, header=None)
    # Loop through the rows and add them to the database
    for i, row in csv_data.iterrows():
        section = Section(
            course_title=csv_data.course_title[i],
            course_id=int(csv_data.course_id[i]),
            dept_id=int(csv_data.dept_id[i]),
            sect_id=int(csv_data.sect_id[i]),
            instructor=csv_data.instructor[i],
            class_period=csv_data.class_period[i]
        )
        db.session.add(section)
        db.session.commit()
    # Delete file after use
    os.remove(file_path)

# Landing page route for SSP
@app.route('/', methods=['GET', 'POST'])
def login():
    page_template = 'base.html'
    form = LoginForm(request.form)
    if current_user.is_authenticated:
        if current_user.access == 'STUDENT':
            # if user is logged in we get out of here
            return redirect(url_for('studentPlanner'))
    if form.validate_on_submit():
        # Verify if user entered correct password
        user = User.query.filter_by(email=form.email.data).first()
        if user is None or not user.verify_password(form.password.data):
            flash('Invalid username or password.')
            return redirect(url_for('login'))
        # Check user access level and if user is confirmed before logging in
        if user.confirmed is False:
            flash('Please confirm your email.')
        if user.access == 'STUDENT' and user.confirmed is True:
            login_user(user)
            flash('You are now logged in!')
            return redirect(url_for('studentPlanner'))
        elif user.access == 'ADMIN' and user.confirmed is True:
            login_user(user)
            flash('You are now logged in!')
            return redirect(url_for('adminCourse'))
        elif user.access == 'ROOT' and user.confirmed is True:
            login_user(user)
            flash('You are now logged in!')
            return redirect(url_for('rootAuth'))
    return render_template(page_template, form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    page_template = 'registration.html'
    form = RegisterForm(request.form)
    if form.validate_on_submit():
        # Check if username or email are already registered
        user = User.query.filter_by(username=form.username.data).first()
        if user is not None:
            flash('Username already exists.')
            return redirect(url_for('register'))
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None:
            flash('Email already exists.')
            return redirect(url_for('register'))
        # Add user into database
        user = User(
            username=form.username.data,
            email=form.email.data,
            password=form.password.data,
            access=form.access.data,
            confirmed=False
        )
        db.session.add(user)
        db.session.commit()
        # Generate confirmation token and url
        token = generate_confirmation_token(user.email)
        confirm_url = url_for('confirm_email', token=token, _external=True)
        # Send confirmation request to students and notification email to root or admin
        if user.access == 'STUDENT':
            html = render_template('activate.html', confirm_url=confirm_url)
            subject = "Please confirm your email"
            send_email(user.email, subject, html)
        elif user.access == 'ADMIN' or user.access == 'ROOT':
            html = render_template('activateRoot.html')
            subject = "Your privileged request has be received"
            send_email(user.email, subject, html)
        return redirect(url_for('login'))

    return render_template(page_template, form=form)


@app.route('/confirm/<token>')
def confirm_email(token):
    # Check integrity of email token/url
    try:
        email = confirm_token(token)
    except token.DoesNotExist:
        flash('The confirmation link is invalid or has expired.', 'danger')
    # Check if user has already confirmed
    user = User.query.filter_by(email=email).first_or_404()
    if user.confirmed:
        flash('Account already confirmed. Please login.', 'success')
    else:
        # Once user is confirmed set confirmed to true and allow them access to application
        user.confirmed = True
        user.confirmed_on = datetime.datetime.now()
        db.session.commit()
        flash('You have confirmed your account. Thanks!', 'success')
    return redirect(url_for('login'))

# TODO set @login_required for all routes for production
@app.route('/root', methods=['GET', 'POST'])
def rootAuth():
    page_template = 'rootAuth.html'
    # Query all users in database to be used in Jinja2
    users = User.query.all()
    return render_template(page_template, users=users)


@app.route('/root_auth_decision', methods=['POST'])
def root_auth_decision():
    if request.method == 'POST':
        query = request.form.get('index')
        user = User.query.filter_by(username=query).first_or_404()
        if request.form.get('accept_button'):
            # Confirm and send notification email
            user.confirmed = True
            user.confirmed_on = datetime.datetime.now()
            html = render_template('approveRoot.html')
            subject = "Your privileged request has be approved"
            send_email(user.email, subject, html)
            db.session.add(user)
            db.session.commit()
            return redirect(url_for('rootAuth'))
        if request.form.get('deny_button'):
            # Send user a message then yeet them
            html = render_template('denyRoot.html')
            subject = "Your privileged request has be denied"
            send_email(user.email, subject, html)
            db.session.delete(user)
            db.session.commit()
            return redirect(url_for('rootAuth'))


@app.route('/rootcourse', methods=['GET', 'POST'])
def rootCourse():
    page_template = 'rootCourse.html'
    courses = Course.query.all()
    rt_crs_add_form = CourseForm(request.form)
    if rt_crs_add_form.validate_on_submit():
        course = Course(
            course_title=rt_crs_add_form.course_title.data,
            dept_id=rt_crs_add_form.dept_id.data,
            course_id=rt_crs_add_form.course_id.data
        )
        db.session.add(course)
        db.session.commit()
        return redirect(url_for('rootCourse'))
    return render_template(page_template, rt_crs_add_form=rt_crs_add_form, courses=courses)


@app.route('/update_course', methods=['POST'])
def update_course():
    if request.method == 'POST':
        query = request.form.get('index')
        course = Course.query.filter_by(course_id=query).first_or_404()
        if request.form.get('edit_button'):
            course.course_title = request.form['course_title']
            course.dept_id = request.form['dept_id']
            course.course_id = request.form['course_id']
            db.session.commit()
            return redirect(url_for('rootCourse'))
        if request.form.get('delete_button'):
            db.session.delete(course)
            db.session.commit()
            return redirect(url_for('rootCourse'))


@app.route("/upload_file", methods=['POST'])
def upload_files():
    # get the uploaded file
    uploaded_file = request.files['file']
    if uploaded_file.filename != '':
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], uploaded_file.filename)
        # set the file path
        uploaded_file.save(file_path)
        parseCSV(file_path)
    # save the file
    return redirect(url_for('adminSection'))


@app.route("/upload_file_root", methods=['POST'])
def upload_files_root():
    # get the uploaded file
    uploaded_file = request.files['file']
    if uploaded_file.filename != '':
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], uploaded_file.filename)
        # set the file path
        uploaded_file.save(file_path)
        parseCSV(file_path)
    # save the file
    return redirect(url_for('rootSection'))


@app.route('/rootsection', methods=['GET', 'POST'])
def rootSection():
    page_template = 'rootSection.html'
    sections = Section.query.all()
    rt_sect_add_form = SectionForm(request.form)
    if rt_sect_add_form.validate_on_submit():
        rt_add_section = Section(
            course_title=rt_sect_add_form.course_title.data,
            course_id=rt_sect_add_form.course_id.data,
            dept_id=rt_sect_add_form.dept_id.data,
            sect_id=rt_sect_add_form.sect_id.data,
            instructor=rt_sect_add_form.instructor.data,
            class_period=rt_sect_add_form.class_period.data
        )
        db.session.add(rt_add_section)
        db.session.commit()
        return redirect(url_for('rootSection'))
    return render_template(page_template, root_section_form=rt_sect_add_form, sections=sections)


@app.route('/root_update_section', methods=['POST'])
def root_update_section():
    if request.method == 'POST':
        query = request.form.get('index')
        section = Section.query.filter_by(sect_id=query).first_or_404()
        if request.form.get('edit_button'):
            section.course_title = request.form['course_title']
            section.course_id = request.form['course_id']
            section.dept_id = request.form['dept_id']
            section.sect_id = request.form['sect_id']
            section.instructor = request.form['instructor']
            section.class_period = request.form['class_period']
            db.session.commit()
            return redirect(url_for('rootSection'))
        if request.form.get('delete_button'):
            db.session.delete(section)
            db.session.commit()
            return redirect(url_for('rootSection'))


@app.route('/admincourse', methods=['GET', 'POST'])
def adminCourse():
    page_template = 'adminCourse.html'
    courses = Course.query.all()
    ad_crs_add_form = CourseForm(request.form)
    if ad_crs_add_form.validate_on_submit():
        course = Course(
            course_title=ad_crs_add_form.course_title.data,
            dept_id=ad_crs_add_form.dept_id.data,
            course_id=ad_crs_add_form.course_id.data
        )
        db.session.add(course)
        db.session.commit()
        return redirect(url_for('adminCourse'))
    return render_template(page_template, ad_crs_add_form=ad_crs_add_form, courses=courses)


@app.route('/admin_update_course', methods=['POST'])
def admin_update_course():
    if request.method == 'POST':
        query = request.form.get('index')
        course = Course.query.filter_by(course_id=query).first_or_404()
        if request.form.get('edit_button'):
            course.course_title = request.form['course_title']
            course.dept_id = request.form['dept_id']
            course.course_id = request.form['course_id']
            db.session.commit()
            return redirect(url_for('adminCourse'))
        if request.form.get('delete_button'):
            db.session.delete(course)
            db.session.commit()
            return redirect(url_for('adminCourse'))


@app.route('/adminsection', methods=['GET', 'POST'])
def adminSection():
    page_template = 'adminSection.html'
    sections = Section.query.all()
    ad_sect_add_form = SectionForm(request.form)
    if ad_sect_add_form.validate_on_submit():
        section = Section(
            course_title=ad_sect_add_form.course_title.data,
            course_id=ad_sect_add_form.course_id.data,
            dept_id=ad_sect_add_form.dept_id.data,
            sect_id=ad_sect_add_form.sect_id.data,
            instructor=ad_sect_add_form.instructor.data,
            class_period=ad_sect_add_form.class_period.data
        )
        db.session.add(section)
        db.session.commit()
        return redirect(url_for('adminSection'))
    return render_template(page_template, ad_sect_add_form=ad_sect_add_form, sections=sections)


@app.route('/admin_update_section', methods=['POST'])
def admin_update_section():
    if request.method == 'POST':
        query = request.form.get('index')
        section = Section.query.filter_by(sect_id=query).first_or_404()
        if request.form.get('edit_button'):
            section.course_title = request.form['course_title']
            section.course_id = request.form['course_id']
            section.dept_id = request.form['dept_id']
            section.sect_id = request.form['sect_id']
            section.instructor = request.form['instructor']
            section.class_period = request.form['class_period']
            db.session.commit()
            return redirect(url_for('adminSection'))
        if request.form.get('delete_button'):
            db.session.delete(section)
            db.session.commit()
            return redirect(url_for('adminSection'))


@app.route('/studentplan', methods=['GET', 'POST'])
def studentPlanner():
    page_template = 'studentPlanner.html'
    breaks = Break.query.all()
    break_form = BreakForm(request.form)
    if break_form.validate_on_submit():
        add_break = Break(
            user_id=break_form.user_id.data,
            break_name=break_form.break_name.data,
            break_period=break_form.break_period.data
        )
        db.session.add(add_break)
        db.session.commit()
        return redirect(url_for('studentPlanner'))
    return render_template(page_template, break_form=break_form, breaks=breaks)

@app.route('/break_update', methods=['POST'])
def break_update():
    if request.method == 'POST':
        query = request.form.get('index')
        breaks = Break.query.filter_by(break_name=query).first_or_404()
        if request.form.get('edit_button'):
            breaks.break_name = request.form['break_name']
            breaks.break_period = request.form['break_period']
            db.session.commit()
            return redirect(url_for('studentPlanner'))
        if request.form.get('delete_button'):
            db.session.delete(breaks)
            db.session.commit()
            return redirect(url_for('studentPlanner'))


@app.route('/studentgen')
def studentGenerate():
    page_template = 'studentGenerate.html'
    return render_template(page_template)


@app.route('/studentcur')
def studentCurrent():
    page_template = 'studentCurrent.html'
    return render_template(page_template)


# TODO OPTIONAL edit error handling pages to be more acceptable
@app.errorhandler(404)
def page_not_found_error(error):
    page_template = '404.html'
    return render_template(page_template, error=error)


@app.errorhandler(500)
def internal_server_error(error):
    page_template = '500.html'
    return render_template(page_template, error=error)


# Create database if it does not exist
db.create_all()


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=4000)