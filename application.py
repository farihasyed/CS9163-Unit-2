from flask import Flask, render_template, request, url_for, redirect, session, flash, make_response

from spell_check import clean, login_required, spell_check_user_input, headers, register_with_user_info, verify_login


MAX_CREDENTIAL_LENGTH = 32
PHONE_LENGTH = 10
PHONE_VALUE = 999999999
MAX_INPUT_LENGTH = 128
service_referrer = {'spell_check': 'spell_check.html'}
session_token = {}


def create_app():
    app = Flask(__name__)
    app.config.update(
        #SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Strict')
    app.config.from_mapping(SECRET_KEY='dev')
    return app


app = create_app()
if __name__ == "__main__":
    app.run(host="localhost")


@app.route('/')
def start():
    return redirect(url_for("login"))


def print_cookies():
    print(request.cookies)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username, password, phone = clean(request.values['uname'], request.values['pword'], request.values['2fa'])
        print("post login cookies")
        print_cookies()
        return verify_login(username, password, phone)
    response = make_response(render_template('login.html'))
    response = headers(response)
    print("get login cookies")
    print_cookies()
    return response


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username, password, phone = clean(request.values['uname'], request.values['pword'], request.values['2fa'])
        return register_with_user_info(username, password, phone)
    response = make_response(render_template('register.html'))
    response = headers(response)
    return response


@app.route('/spell_check', methods=['GET', 'POST'])
@login_required
def spell_check():
    if request.method == 'POST':
        file_path = "text/samples/file.txt"
        print("post spell check cookies")
        print_cookies()
        return spell_check_user_input(request.form['inputtext'], file_path)
    response = make_response(render_template('spell_check.html', user=session['user']['username']))
    response = headers(response)
    print("get spell check cookies")
    print_cookies()
    return response


@app.route('/logout', methods=['POST'])
def logout():
    print("prelogout cookies")
    print_cookies()
    session.pop('user', None)
    flash("You have been logged out.", 'failure')
    print("postlogout cookies")
    print_cookies()
    return redirect(url_for('start'))