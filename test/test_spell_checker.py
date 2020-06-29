import pytest
from flask import Flask
import spell_checker

app = Flask(__name__)
usernames = ['farihasyed', 'nyu', 'unc', 'dook']
passwords = ['music', 'nyu', 'dooksucks', 'uncisawesome']
phones = ['919-308-9764', '123-456-7890', '234-567-8910', '922-123-1995']
correct_credentials = 3
credentials = {}

for i in range(correct_credentials):
    credentials[usernames[i]] = {'password': passwords[i], 'phone': phones[i]}


@pytest.fixture
def client():
    spell_checker.app.config['TESTING'] = True
    with spell_checker.app.test_client() as client:
        yield client


def register(client, username, password, phone=''):
    return client.post('/register', data={
        'uname': username,
        'pword': password,
        'phone': phone
    }, follow_redirects=True)


def test_register_get(client):
    response = client.get('/register')
    assert response.status_code == 200
    assert b"User Registration" in response.data


def test_register_post(client):
    response = register(client, usernames[0], passwords[0], phones[0])
    assert b'Congratulations! You have been successfully registered.' in response.data
    assert b'Click' in response.data
    assert b'to return to the login page.' in response.data
    response = register(client=client, username=usernames[1], password=passwords[1])
    assert b'Congratulations! You have been successfully registered.' in response.data
    assert b'Click' in response.data
    assert b'to return to the login page.' in response.data
    response = register(client=client, username='', password=passwords[1])
    assert b'A username is required to register.' in response.data
    assert b'Alternatively, click' in response.data
    assert b'to return to the login page.' in response.data
    response = register(client, username=usernames[2], password='', phone='')
    assert b'A password is required to register.' in response.data
    assert b'Alternatively, click' in response.data
    assert b'to return to the login page.' in response.data
    response = register(client=client, username=usernames[0], password=passwords[3])
    assert b'Username already taken. Please choose another one.' in response.data
    assert b'Alternatively, click' in response.data
    assert b'to return to the login page.' in response.data


def login(client, username, password='', phone=''):
    return client.post('/login', data={
        'uname': username,
        'pword': password,
        'phone': phone
    }, follow_redirects=True)


def test_login_get(client):
    response = client.get('/login')
    assert response.status_code == 200
    assert b'Sign in below or' in response.data
    # assert b'register for a new account' in response.data


def test_login_post_success(client):
    response = login(client=client, username=usernames[0], password=passwords[0], phone=phones[0])
    assert b'You have been successfully logged in.' in response.data
    assert b'Click' in response.data
    assert b'to access the spell checker.' in response.data
    response = login(client=client, username=usernames[0], phone=phones[0])
    assert b'You have been successfully logged in.' in response.data
    assert b'Click' in response.data
    assert b'to access the spell checker.' in response.data


def test_login_post_failure(client):
    response = login(client=client, username=usernames[3], password=passwords[3])
    assert b'Incorrect username and/or password. Please try again.' in response.data
    response = login(client=client, username=usernames[0], password=passwords[1])
    assert b'Incorrect username and/or password. Please try again.' in response.data
    response = login(client=client, username=usernames[0], phone=phones[1])
    assert b'Two-factor authentication failure' in response.data


def test_spell_check_get(client):
    response = client.get('/spell_check')
    assert response.status_code == 200
    assert b'Enter text to be spell checked.' in response.data


def test_spell_check_post(client):
    input = 'Take a sad sogn and make it better. Remember to let her under your skyn, then you begin to make it betta.'
    response = spell_check(client, input)
    assert b'Results' in response.data
    assert b'Input: Take a sad sogn and make it better. Remember to let her under your skyn, then you begin to make it betta.' in response.data
    assert b'The following 3 words were misspelled: sogn, skyn, betta'


def spell_check(client, input):
    return client.post('/spell_check', data={'inputtext': input}, follow_redirects=True)