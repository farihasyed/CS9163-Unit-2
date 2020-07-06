from flask import request, url_for, redirect, session, g, flash
import subprocess
from subprocess import Popen
import functools
import bleach
from secrets import token_hex
from security import session_token

credentials = {}


def verify_login(username, password, phone):
    failure = 'Incorrect username, password, and/or phone. Please try again.'
    if username in credentials:
        user = credentials[username]
        if user['password'] == password or user['phone'] == phone:
            success = 'Success! You have been logged in.'
            token = str(token_hex(32))
            session['user'] = {'username': str(username), 'remote address': request.remote_addr, 'token': token}
            session_token[str(username)] = {'username': str(username), 'remote address': request.remote_addr, 'token': token}
            g.user = session['user']
            flash(success, 'success')
            return redirect(url_for('login'))
        elif phone is not None and phone != user['phone']:
            failure = 'Two-factor authentication failure.'
    flash(failure, 'failure')
    return redirect(url_for('login'))


def register_with_user_info(username, password, phone):
    if username in credentials:
        failure = 'Username already taken. Please choose another one.'
    else:
        credentials[username] = {'username': username, 'password': password, 'phone': phone}
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
            flash("You must be logged in to view this page.", 'failure')
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view


def clean(input):
    return bleach.clean(input)


def spell_check_user_input(input, file_path):
    input = clean(input)
    file = open(file_path, "w")
    file.write(clean(input))
    file.close()
    input = 'Input text: ' + input
    process = Popen(["#!/bin/sh\n./a.out", file_path, "text/wordlist.txt"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    universal_newlines=True)
    output, errors = process.communicate()
    if len(output) == 0:
        output = 'Could not spell check invalid input.'
    flash(output, 'output')
    flash(input, 'input')
    return redirect(url_for('spell_check'))


def cleanup():
    if 'user' in session:
        user = session.get("user")
        session_token.pop(user['username'])
        session.pop('user')