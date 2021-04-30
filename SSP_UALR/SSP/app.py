# Library Imports
import random

import flask
import wtforms.widgets
from flask import Flask, render_template, flash, request, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from flask_mail import Mail, Message
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, SubmitField, SelectMultipleField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash, check_password_hash

import os
import datetime
import pandas as pd
import time

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
    email = db.Column(db.String(64), index=True)
    first_name = db.Column(db.String(64))
    last_name = db.Column(db.String(64))
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
    user_id = db.Column(db.String(64), db.ForeignKey('users.id'))
    rows_id = db.Column(db.Integer,  primary_key=True) #db.ForeignKey('section.row_id'),
    course_title = db.Column(db.String(64))
    course_id = db.Column(db.Integer)
    dept_id = db.Column(db.String(64))
    sect_id = db.Column(db.String(64))
    instructor = db.Column(db.String(64))
    class_period = db.Column(db.String(64))


class Break(db.Model):
    __tablename__ = 'breaks'
    user_id = db.Column(db.String(64), db.ForeignKey('users.id'), primary_key=True)
    break_name = db.Column(db.String(64), primary_key=True)
    break_day = db.Column(db.String(64))
    break_start_time = db.Column(db.String(64))
    break_end_time = db.Column(db.String(64))


class GeneratedSchedules(db.Model):
    __tablenamme__ = 'generated_schedules'
    user_id = db.Column(db.String(64), db.ForeignKey('users.id'))
    rows_id = db.Column(db.Integer, primary_key=True)
    course_title = db.Column(db.String(64))
    course_id = db.Column(db.Integer)
    dept_id = db.Column(db.String(64))
    sect_id = db.Column(db.String(64))
    instructor = db.Column(db.String(64))
    class_period = db.Column(db.String(64))
    break_name = db.Column(db.String(64))
    reserved_time = Break(
        break_name=db.Column(db.String(64)),
        break_day=db.Column(db.String(64)),
        break_start_time=db.Column(db.String(64)),
        break_end_time=db.Column(db.String(64))
    )


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
    course_id = db.Column(db.Integer)
    row_id = db.Column(db.Integer, autoincrement=True, primary_key=True)


# User loader callback for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# WTF flask forms
class RegisterForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(), Length(1, 64)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(1, 64)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    password_again = PasswordField('Confirm Password',
                                   validators=[DataRequired(), EqualTo('password')])
    access = SelectField('Access Level', choices=[('STUDENT', 'STUDENT'), ('ROOT', 'ROOT'), ('ADMIN', 'ADMIN')])
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
    class_period = StringField('Class Period -- MWF or TR HH:MM - HH:MM (UTC)', validators=[DataRequired()])
    submit = SubmitField('Add')


class CourseForm(FlaskForm):
    course_title = StringField('Course Title', validators=[DataRequired()])
    dept_id = StringField('Department ID', validators=[DataRequired()])
    course_id = StringField('Course ID', validators=[DataRequired()])
    submit = SubmitField('Add')


class BreakForm(FlaskForm):
    time_choices = [('8:00', '08:00'), ('8:30', '08:30'), ('9:00', '09:00'), ('9:30', '09:30'), ('10:00', '10:00'),
                    ('10:30', '10:30'), ('11:00', '11:00'), ('11:30', '11:30'), ('12:00', '12:00'), ('12:30', '12:30'),
                    ('13:00', '13:00'), ('13:30', '13:30'), ('14:00', '14:00'), ('14:30', '14:30'), ('15:00', '15:00'),
                    ('15:30', '15:30'), ('16:00', '16:00'), ('16:30', '16:30'), ('17:00', '17:00'), ('17:30', '17:30'),
                    ('18:00', '18:00'), ('18:30', '18:30'), ('19:00', '19:00'), ('19:30', '19:30'), ('20:00', '20:00')]
    day_choices = [('M', 'Monday'), ('T', 'Tuesday'), ('W', 'Wednesday'), ('R', 'Thursday'), ('F', 'Friday'),
                   ('S', 'Saturday'), ('Su', 'Sunday')]
    break_name = StringField('Break Name', validators=[DataRequired()])
    break_day = SelectMultipleField('Days', choices=day_choices, validators=[DataRequired()])
    break_start_time = SelectField('Start Time: HH:MM (UTC)', choices=time_choices, validators=[DataRequired()])
    break_end_time = SelectField('End Time: HH:MM (UTC)', choices=time_choices, validators=[DataRequired()])
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


# Convert HH:MM to minutes
def military_time_converter(new_time):
    x = new_time
    t = time.strptime(new_time, "%H:%M")
    minutes = t.tm_hour * 60 + t.tm_min
    return minutes


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


# Parse CSV file on upload
def parse_course_CSV(file_path):
    # CVS column names
    col_names = ['course_title', 'dept_id', 'course_id']
    # Use Pandas to parse the CSV file
    csv_data = pd.read_csv(file_path, names=col_names, header=None)
    # Loop through the rows and add them to the database
    for i, row in csv_data.iterrows():
        course = Course(
            course_title=csv_data.course_title[i],
            course_id=int(csv_data.course_id[i]),
            dept_id=int(csv_data.dept_id[i])
        )
        db.session.add(course)
        db.session.commit()
    # Delete file after use
    os.remove(file_path)


# Default route and login page for PUBLIC_USER -> USER
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
            flash('Invalid username or password.', 'alert-danger')
            return redirect(url_for('login'))
        # Check user access level and if user is confirmed before logging in
        if user.confirmed is False:
            flash('Please confirm your email.' 'alert-warning')
        if user.access == 'STUDENT' and user.confirmed is True:
            login_user(user)
            return redirect(url_for('studentPlanner'))
        elif user.access == 'ADMIN' and user.confirmed is True:
            login_user(user)
            return redirect(url_for('course_catalog'))
        elif user.access == 'ROOT' and user.confirmed is True:
            login_user(user)
            return redirect(url_for('rootAuth'))
    return render_template(page_template, form=form)


# Route for PUBLIC_USER to register as either ROOT, ADMIN, or STUDENT
@app.route('/register', methods=['GET', 'POST'])
def register():
    page_template = 'registration.html'
    form = RegisterForm(request.form)
    if form.validate_on_submit():
        # Check if username or email are already registered
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None:
            flash('The email address you have entered already exists. Please login or use another email address.',
                  'alert-danger')
            return redirect(url_for('register'))
        # Add user into database
        user = User(
            first_name=form.first_name.data,
            last_name=form.last_name.data,
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
            html = render_template('activate.html', confirm_url=confirm_url, first_name=user.first_name)
            subject = "Please confirm your email"
            send_email(user.email, subject, html)
        elif user.access == 'ADMIN' or user.access == 'ROOT':
            html = render_template('activateRoot.html', first_name=user.first_name)
            subject = "Your privileged request has been received"
            send_email(user.email, subject, html)
        return redirect(url_for('login'))
    return render_template(page_template, form=form)


# Route for email confirmation to verify user
@app.route('/confirm/<token>')
def confirm_email(token):
    # Check integrity of email token/url
    try:
        email = confirm_token(token)
    except token.DoesNotExist:
        flash('The confirmation link is invalid or has expired.', 'alert-danger')
    # Check if user has already confirmed
    user = User.query.filter_by(email=email).first_or_404()
    if user.confirmed:
        flash('Account already confirmed. Please login.', 'alert-success')
    else:
        # Once user is confirmed set confirmed to true and allow them access to application
        user.confirmed = True
        user.confirmed_on = datetime.datetime.now()
        db.session.commit()
        flash('Your account is now confirmed ', 'alert-success')
    return redirect(url_for('login'))


# TODO set @login_required for all routes for root auth
@app.route('/root', methods=['GET', 'POST'])
# @login_required
def rootAuth():
    # if current_user.is_authenticated:
    # if current_user.access == 'ROOT':
    page_template = 'rootAuth.html'
    # Query all users in database to be used in Jinja2
    users = User.query.all()
    return render_template(page_template, users=users)


# elif current_user.access == 'ADMIN':
#  return redirect(401)
# elif current_user.access == 'STUDENT':
#   return redirect(401)


# POST route for root decision on privileged user requests
@app.route('/root_auth_decision', methods=['POST'])
def root_auth_decision():
    if request.method == 'POST':
        query = request.form.get('index')
        user = User.query.filter_by(email=query).first_or_404()
        if request.form.get('accept_button'):
            # Confirm and send notification email
            user.confirmed = True
            user.confirmed_on = datetime.datetime.now()
            # Generate confirmation token and url
            html = render_template('approveRoot.html', first_name=user.first_name)
            subject = "Your privileged request has been approved"
            send_email(user.email, subject, html)
            db.session.add(user)
            db.session.commit()
            flash('User request has been approved', 'alert-success')
            return redirect(url_for('rootAuth'))
        if request.form.get('deny_button'):
            # Send user a message then yeet them
            html = render_template('denyRoot.html', first_name=user.first_name)
            subject = "Your privileged request has been denied"
            send_email(user.email, subject, html)
            db.session.delete(user)
            db.session.commit()
            flash('User request has been denied', 'alert-danger')
            return redirect(url_for('rootAuth'))


# Route for root or admin to view, add, or edit courses
@app.route('/courses', methods=['GET', 'POST'])
@login_required
def course_catalog():
    if current_user.is_authenticated:
        if current_user.access == 'ROOT' or current_user.access == 'ADMIN':
            page_template = 'course_catalog.html'
            courses = Course.query.all()
            rt_crs_add_form = CourseForm(request.form)
            if rt_crs_add_form.validate_on_submit():
                course_query = Section.query.filter_by(row_id=rt_crs_add_form.course_id.data).first()
                if course_query is not None:
                    flash('Course already exists!', 'alert-danger')
                else:
                    course = Course(
                        course_title=rt_crs_add_form.course_title.data,
                        dept_id=rt_crs_add_form.dept_id.data,
                        course_id=rt_crs_add_form.course_id.data
                    )
                    db.session.add(course)
                    db.session.commit()
                    flash('Course successfully added!', 'alert-success')
                return redirect(url_for('course_catalog'))
            return render_template(page_template, rt_crs_add_form=rt_crs_add_form, courses=courses)
        else:
            return redirect(url_for('unauthorized_error'))


# POST route for root course update
@app.route('/update_course', methods=['POST'])
@login_required
def update_course():
    if current_user.is_authenticated:
        if current_user.access == 'ROOT' or current_user.access == 'ADMIN':
            if request.method == 'POST':
                query = request.form.get('index')
                course = Course.query.filter_by(row_id=query).first_or_404()
                if request.form.get('edit_button'):
                    course.course_title = request.form['course_title']
                    course.dept_id = request.form['dept_id']
                    course.course_id = request.form['course_id']
                    db.session.commit()
                    flash('Course successfully edited!', 'alert-success')
                    return redirect(url_for('course_catalog'))
                if request.form.get('delete_button'):
                    db.session.delete(course)
                    db.session.commit()
                    flash('Course deleted!', 'alert-danger')
                    return redirect(url_for('course_catalog'))
            else:
                return redirect(url_for('unauthorized_error'))


# POST route for CSV file upload
@app.route("/upload_file", methods=['POST'])
@login_required
def upload_files():
    if current_user.is_authenticated:
        if current_user.access == 'ROOT' or current_user.access == 'ADMIN':
            # Get the uploaded file
            uploaded_file = request.files['file']
            if uploaded_file.filename != '':
                # Set the file path
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], uploaded_file.filename)
                # Save the file
                uploaded_file.save(file_path)
                # Parse the CSV file using Pandas
                parseCSV(file_path)
                flash('File imported successfully!', 'alert-success')
                return redirect(url_for('sections_catalog'))
        # else:
        #     return redirect(url_for('unauthorized_error'))


# POST route for course CSV file upload
@app.route("/upload_course_files", methods=['POST'])
@login_required
def upload_course_files():
    if current_user.is_authenticated:
        if current_user.access == 'ROOT' or current_user.access == 'ADMIN':
            # Get the uploaded file
            uploaded_file = request.files['file']
            if uploaded_file.filename != '':
                # Set the file path
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], uploaded_file.filename)
                # Save the file
                uploaded_file.save(file_path)
                # Parse the CSV file using Pandas
                parse_course_CSV(file_path)
                flash('File imported successfully!', 'alert-success')
                return redirect(url_for('course_catalog'))
        else:
            return redirect(url_for('unauthorized_error'))


# Route for root or admin to view, add, or edit sections
@app.route('/sections', methods=['GET', 'POST'])
@login_required
def sections_catalog():
    if current_user.is_authenticated:
        if current_user.access == 'ROOT' or current_user.access == 'ADMIN':
            page_template = 'section_catalog.html'
            sections = Section.query.all()
            rt_sect_add_form = SectionForm(request.form)
            if rt_sect_add_form.validate_on_submit():
                section = Section.query.filter_by(row_id=rt_sect_add_form.sect_id.data).first()
                if section is not None:
                    flash('Section already exists!', 'alert-danger')
                else:
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
                    flash('Section successfully added!', 'alert-success')
                return redirect(url_for('sections_catalog'))
            return render_template(page_template, root_section_form=rt_sect_add_form, sections=sections)
        else:
            return redirect(url_for('unauthorized_error'))


# POST route for root or admin to update sections
@app.route('/update_section', methods=['POST'])
@login_required
def update_section():
    if current_user.is_authenticated:
        if current_user.access == 'ROOT' or current_user.access == 'ADMIN':
            if request.method == 'POST':
                query = request.form.get('index')
                section = Section.query.filter_by(row_id=query).first_or_404()
                if request.form.get('edit_button'):
                    section.course_title = request.form['course_title']
                    section.course_id = request.form['course_id']
                    section.dept_id = request.form['dept_id']
                    section.sect_id = request.form['sect_id']
                    section.instructor = request.form['instructor']
                    section.class_period = request.form['class_period']
                    db.session.commit()
                    flash('Section successfully edited!', 'alert-success')
                    return redirect(url_for('sections_catalog'))
                if request.form.get('delete_button'):
                    db.session.delete(section)
                    db.session.commit()
                    flash('Section deleted!', 'alert-danger')
                    return redirect(url_for('sections_catalog'))
        else:
            return redirect(url_for('unauthorized_error'))


# Route for student planner
@app.route('/studentplan', methods=['GET', 'POST'])
@login_required
def studentPlanner():
    if current_user.is_authenticated:
        if current_user.access == 'STUDENT':
            page_template = 'studentPlanner.html'
            # Select all of the student's breaks based on their assigned ID
            query = current_user.id
            breaks = Break.query.filter_by(user_id=query).all()
            break_form = BreakForm(request.form)
            if break_form.validate_on_submit():
                check_break_name = Break.query.filter_by(break_name=break_form.break_name.data).first()
                if check_break_name is not None:
                    flash('break_name already exists.', 'alert-danger')
                    return redirect(url_for('studentPlanner'))
                check_break_st = military_time_converter(break_form.break_start_time.data)
                check_break_et = military_time_converter(break_form.break_end_time.data)
                if check_break_et == check_break_st:
                    flash('break_period must be different.', 'alert-danger')
                    return redirect(url_for('studentPlanner'))
                if check_break_st > check_break_et:
                    flash('Start time must be less than End time.', 'alert-danger')
                    return redirect(url_for('studentPlanner'))
                add_break = Break(
                    user_id=current_user.id,
                    break_name=break_form.break_name.data,
                    break_day=''.join(break_form.break_day.data),
                    break_start_time=break_form.break_start_time.data,
                    break_end_time=break_form.break_end_time.data
                )
                db.session.add(add_break)
                db.session.commit()
                flash('Break was successfully Added', 'alert-success')
                return redirect(url_for('studentPlanner'))
            add_class = AddClass.query.all()
            section = Section.query.all()
            return render_template(page_template, break_form=break_form, breaks=breaks, add_classes=add_class, sections=section)
        else:
            return redirect(url_for('unauthorized_error'))


# POST route for updating student breaks
@app.route('/break_update', methods=['POST'])
def break_update():
    if current_user.is_authenticated:
        if current_user.access == 'STUDENT':
            if request.method == 'POST':
                query = request.form.get('index')
                breaks = Break.query.filter_by(break_name=query).first_or_404()
                if request.form.get('edit_button'):
                    breaks.break_name = request.form['break_name']
                    breaks.break_day = ''.join(request.form.getlist('break_day'))
                    breaks.break_start_time = request.form['break_start_time']
                    breaks.break_end_time = request.form['break_end_time']
                    flash('Break was successfully edited', 'alert-success')
                    db.session.commit()
                    return redirect(url_for('studentPlanner'))
                if request.form.get('delete_button'):
                    db.session.delete(breaks)
                    db.session.commit()
                    flash('Break was successfully deleted', 'alert-success')
                    return redirect(url_for('studentPlanner'))
        else:
            return redirect(url_for('unauthorized_error'))


@app.route('/plan_course')
def plan_course():
    if current_user.is_authenticated:
         if current_user.access == 'STUDENT':
             page_template = 'studentSection.html'
             sections = Section.query.all()
             return render_template(page_template, sections=sections)
    else:
        return redirect(url_for('unauthorized_error'))


@app.route('/plan_course_delete', methods=['POST'])
def plan_course_update():
    if current_user.is_authenticated:
        if current_user.access == 'STUDENT':
            if request.method == 'POST':
                query = request.form.get('index')
                addClass = AddClass.query.filter_by(rows_id=query).first_or_404()
                if request.form.get('sect_delete_button'):
                    db.session.delete(addClass)
                    db.session.commit()
                    flash('Course was successfully deleted', 'alert-success')
                    return redirect(url_for('studentPlanner'))
    else:
        return redirect(url_for('unauthorized_error'))


@app.route('/plan_add_course', methods=['GET', 'POST'])
def plan_add_course():
    if current_user.is_authenticated:
        if current_user.access == 'STUDENT':
        # Select all of the student's breaks based on their assigned ID
            if request.method == 'POST':
                qry = request.form.get('index')
                section = Section.query.filter_by(row_id=qry).first_or_404()
                if request.form.get('add_button'):
                    check = AddClass.query.filter_by(rows_id=qry).first()
                    if check is None: #If unique ROWS_ID
                        add_class = AddClass(
                            user_id=current_user.id,
                            rows_id=section.row_id,
                            course_title=section.course_title,
                            course_id=section.course_id,
                            dept_id=section.dept_id,
                            sect_id=section.sect_id,
                            instructor=section.instructor,
                            class_period=section.class_period
                        )
                        db.session.add(add_class)
                        db.session.commit()
                        flash('Course was successfully Added', 'alert-success')
                        return redirect(url_for('studentPlanner'))
                    else:   # If not unique ROWS_ID
                        flash('Course already exists.', 'alert-danger')
                        return redirect(url_for('studentPlanner'))
    else:
        return redirect(url_for('unauthorized_error'))


# Route for PUBLIC_USER to view all courses
@app.route('/all')
def public():
    page_template = 'public.html'
    courses = Course.query.all()
    return render_template(page_template, courses=courses)


# Route for student schedule generation
@app.route('/studentgen')
@login_required
def studentGenerate():
    if current_user.is_authenticated:
        if current_user.access == 'STUDENT':
            if request.method == 'POST':
                page_template = 'studentGenerate.html'
                return render_template(page_template)
        else:
            return redirect(url_for('unauthorized_error'))


@app.route("/generate_schedule", methods=['POST'])
def generate_schedules():
    if current_user.is_authenticated:
         if current_user.access == 'STUDENT':
            query = current_user.id
            breaks = Break.query.filter_by(user_id=query).all()
            addClass = AddClass.query.filter_by(user_id=query).all()
            page_template = 'studentGenerate.html'
            for addClasses in addClass:
                class_period = addClass.class_period
                day, break_time = class_period.split(' ')
                start_time, end_time = break_time.split('-')
                for student_break in breaks:
                    if start_time > breaks.break_start_time or start_time < breaks.break_end_time:
                        flash('A desired course is between your break.', 'alert-danger')
                        return render_template(page_template)
                    else:
                        generate_schedule = GeneratedSchedules(
                            course_title=addClass.course_title,
                            course_id=addClass.course_id,
                            dept_id=addClass.dept_id,
                            sect_id=addClass.sect_id,
                            instructor=addClass.instructor,
                            class_period=addClass.class_period
                        )
                        db.session.add(generate_schedule)
                        db.session.commit()
            return render_template(page_template)


# Route for student schedule viewer
@app.route('/studentcur')
def studentCurrent():
    if current_user.is_authenticated:
        if current_user.access == 'STUDENT':
            page_template = 'studentCurrent.html'
            return render_template(page_template)
        else:
            return redirect(url_for('unauthorized_error'))


# User logout route
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


# Application common error handling routes
@app.errorhandler(401)
def unauthorized_error(error):
    page_template = '401.html'
    return render_template(page_template, error=error)


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

# Application run on host IP address port 5000
if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)