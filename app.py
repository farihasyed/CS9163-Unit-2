from flask import Flask, render_template, request, url_for, redirect, session, make_response
from flask_wtf import CSRFProtect
from forms import Registration, Login, SpellCheck
from spell_check import login_required, spell_check_user_input, register_with_user_info, verify_login, cleanup
from security import check_referrer, check_user, headers
import os


def create_app():
    app = Flask(__name__)
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Strict')
    app.config.from_mapping(SECRET_KEY=os.environ["SECRET_KEY"])
    csrf = CSRFProtect()
    csrf.init_app(app)
    return app, csrf


app, csrf = create_app()
if __name__ == "__main__":
    app.run(host='localhost')


@app.route('/')
def start():
    return redirect(url_for("login"))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = Login()
    if check_referrer():
        if form.validate_on_submit():
            username, password, phone = form.username.data, form.password.data, form.phone.data
            return verify_login(username, password, phone)
        response = make_response(render_template('login.html', form=form))
        response = headers(response)
        return response
    return "CSRF attack thwarted"


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = Registration()
    if check_referrer():
        if form.validate_on_submit():
            username, password, phone = form.username.data, form.password.data, form.phone.data
            return register_with_user_info(username, password, phone)
        response = make_response(render_template('register.html', form=form))
        response = headers(response)
        return response
    return "CSRF attack thwarted"


@app.route('/spell_check', methods=['GET', 'POST'])
@login_required
def spell_check():
    form = SpellCheck()
    if check_user():
        if form.validate_on_submit():
            file_path = "text/samples/file.txt"
            return spell_check_user_input(form.input.data, file_path)
        response = make_response(render_template('spell_check.html', user=session['user']['username'], form=form))
        response = headers(response)
        return response
    return "CSRF attack thwarted"


@csrf.exempt
@app.route('/logout', methods=['GET', 'POST'])
def logout():
    if request.method == 'POST':
        response = make_response(render_template('logout.html'))
        response = headers(response)
        cleanup()
        return response
    return redirect(url_for('login'))


