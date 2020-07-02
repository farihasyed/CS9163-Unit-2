from flask import Flask, render_template, request, url_for, redirect, session, g, flash, make_response, escape
import subprocess
from subprocess import Popen
import functools
import bleach
import re


MAX_CREDENTIAL_LENGTH = 32
PHONE_LENGTH = 10
PHONE_VALUE = 999999999
MAX_INPUT_LENGTH = 128

def create_app():
    app = Flask(__name__)
    app.config.update(
        #SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Strict')
    app.config.from_mapping(SECRET_KEY='dev')

    return app


credentials = {}
app = create_app()
if __name__ == "__main__":
    app.run(host="localhost")


@app.route('/')
def start():
    return redirect(url_for("login"))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username, password, phone = clean(request.values['uname'], request.values['pword'], request.values['2fa'])
        return verify_login(username, password, phone)
    response = make_response(render_template('login.html'))
    response = headers(response)
    return response


def clean(username, password, phone):
    username = username.lower()
    return bleach.clean(username), bleach.clean(password), bleach.clean(phone)


def validate_username(username):
    return username.isalnum() and len(username) < MAX_CREDENTIAL_LENGTH and len(username) > 0


def validate_password(password):
    return re.match('^[a-zA-Z0-9_!@#$%&*]+$', password) and len(password) < MAX_CREDENTIAL_LENGTH and len(password) > 0


def validate_phone(phone):
    if phone.isdigit():
        return len(phone) == PHONE_LENGTH and int(phone) > PHONE_VALUE
    return len(phone) == 0


def validate_credentials(username, password, phone):
    return validate_username(username) and (validate_password(password) or validate_phone(phone))


def verify_login(username, password, phone):
    failure = 'Incorrect username and/or password. Please try again.'
    if validate_credentials(username, password, phone):
        if username in credentials:
            user = credentials[username]
            if user['password'] == password or (len(phone) != 0 and user['phone'] == int(phone)):
                success = 'Success! You have been logged in.'
                session['user'] = user
                g.user = user
                flash(success, 'success')
                return redirect(url_for('login'))
            elif len(phone) != 0 and user['phone'] != int(phone):
                failure = 'Two-factor authentication failure'
    flash(failure, 'failure')
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username, password, phone = clean(request.values['uname'], request.values['pword'], request.values['2fa'])
        return register_with_user_info(username, password, phone)
    response = make_response(render_template('register.html'))
    response = headers(response)
    return response


def register_with_user_info(username, password, phone):
    if not validate_username(username):
        failure = 'Invalid username. Must be no longer than 32 characters and only alphanumeric characters allowed.'
    elif not validate_password(password):
        failure = 'Invalid password. Must be no longer than 32 characters and only alphanumeric characters and special characters _, !, @, #, $, %, &, and * allowed.'
    elif username in credentials:
        failure = 'Username already taken. Please choose another one.'
    elif not validate_phone(phone):
        failure = 'Invalid phone number. Must be of length 10 and only digits allowed.'
    else:
        credentials[username] = {'username': username, 'password': password, 'phone': '' if len(phone) == 0 else int(phone)}
        success = 'Success! You have been registered.'
        flash(success, 'success')
        return redirect(url_for('register'))
    flash(failure, 'failure')
    return redirect(url_for('register'))


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        user = session.get('user')
        if user is None:
            g.user = None
            flash("You must be logged in to view this page.", 'failure')
            return redirect(url_for('login'))
        else:
            g.user = user
        return view(**kwargs)
    return wrapped_view


def clean_and_escape_user_input(input):
    input = bleach.clean(input)
    return escape(input)


@app.route('/spell_check', methods=['GET', 'POST'])
@login_required
def spell_check():
    if request.method == 'POST':
        file_path = "text/samples/file.txt"
        return spell_check_user_input(request.form['inputtext'], file_path)
    response = make_response(render_template('spell_check.html', user=session['user']['username']))
    response = headers(response)
    return response


def spell_check_user_input(input, file_path):
    if len(input) > MAX_INPUT_LENGTH:
        output = 'Input too long. Please try again.'
    else:
        input = clean_and_escape_user_input(input)
        file = open(file_path, "w")
        file.write(input)
        file.close()
        process = Popen(["./a.out", file_path, "text/wordlist.txt"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        universal_newlines=True)
        output, errors = process.communicate()
        if len(output) == 0:
            output = 'Could not spell check invalid input.'
            input = ''
        else:
            input = 'Input text: ' + input
    flash(output, 'output')
    flash(input, 'input')
    return redirect(url_for('spell_check'))


@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user', None)
    flash("You have been logged out.", 'failure')
    return redirect(url_for('start'))


def headers(response):
    jquery = 'https://code.jquery.com'
    popper = 'https://cdn.jsdelivr.net'
    bootstrap = 'https://stackpath.bootstrapcdn.com'
    separator = ' '
    csp_allowed = separator.join([jquery, popper, bootstrap])
    response.headers['Content-Security-Policy'] = "default-src 'self' script-src 'self' " + csp_allowed + "style-src " + csp_allowed
    response.headers['Strict-Transport-Security'] = 'max-age=3600; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response