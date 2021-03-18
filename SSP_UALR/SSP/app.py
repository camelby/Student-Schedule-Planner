from flask import Flask, render_template
from flask_bootstrap import Bootstrap
import os


# application instance
app = Flask(__name__)
app.secret_key = os.urandom(12)
bootstrap = Bootstrap(app)

# First route users go to
# TODO: Program authentication mechanism
@app.route('/')
def login():
    page_template = 'base.html'
    return render_template(page_template)


@app.route('/register')
def register():
    page_template = 'registration.html'
    return render_template(page_template)

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

@app.errorhandler(404)
def page_not_found_error(error):
    page_template = '404.html'
    return render_template(page_template, error=error)


@app.errorhandler(500)
def internal_server_error(error):
    page_template = '500.html'
    return render_template(page_template, error=error)


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=4000)

