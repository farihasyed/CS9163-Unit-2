from flask import Flask, render_template, request, url_for, redirect, make_response
import subprocess
from subprocess import Popen

app = Flask(__name__)
credentials = {}

if __name__ == "__main__":
    app.run(host="localhost", port=9090, debug=True)


@app.route('/')
def start():
    return redirect(url_for("login"))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.values['uname']
        password = request.values['pword']
        phone = request.values['phone']
        return verify_login(username, password, phone)
    return render_template("login.html")


def verify_login(username, password, phone):
    # made this code prettier
    failure = 'Incorrect username and/or password. Please try again.'
    if username in credentials:
        user = credentials[username]
        if user['password'] == password or user['phone'] == phone:
            success = 'You have been successfully logged in.'
            response = make_response()
            response.set_cookie('userID', username)
            return render_template('login.html', success=success)
        elif password == '' and phone != '':
            failure = 'Two-factor authentication failure.'

    return render_template('login.html', failure=failure)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.values['uname']
        password = request.values['pword']
        phone = request.values['phone']
        return register_with_user_info(username, password, phone)
    return render_template('register.html')


def register_with_user_info(username, password, phone):
    if username in credentials:
        failure = 'Username already taken. Please choose another one.'
        return render_template('register.html', failure=failure)
    if username == '':
        failure = 'A username is required to register.'
        return render_template('register.html', failure=failure)
    if password == '':
        failure = 'A password is required to register.'
        return render_template('register.html', failure=failure)

    credentials[username] = {'password': password, 'phone': phone}
    success = 'Congratulations! You have been successfully registered.'
    return render_template('register.html', success=success)


@app.route('/spell_check', methods=['GET', 'POST'])
def spell_check():
    submissions = 0
    if request.method == 'POST':
        submissions = submissions + 1
        file_path = "text/samples/" + "file" + str(submissions) + ".txt"
        input = request.values['inputtext']
        return spell_check_user_input(input, file_path)
    return render_template("spell_check.html")


def spell_check_user_input(input, file_path):
    file = open(file_path, "w")
    file.write(input)
    file.close()
    process = Popen(["./a.out", file_path, "text/wordlist.txt"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    universal_newlines=True)
    output, errors = process.communicate()
    return render_template("spell_check.html", input=input, output=output)