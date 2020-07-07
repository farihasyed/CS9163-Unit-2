import pytest
from flask import Flask, escape
import application

usernames = ['farihasyed', 'nyu12345', 'uncchapelhill', 'dooksucks', 'unc!!', 'thisusernameislongerthan32characters', 'farihasyed2']
passwords = ['music922', 'nyu12345', 'dooksucks', 'uncisawesome', 'dook<sucks>', '!@#$%&*', 'thispasswordislongerthan32characters']
phones = ['9193089764', '1234567890', '2345678910', '9221231995', '123456789100', '123', '0123456789', 'abc123']
correct_credentials = 3
credentials = {}

for i in range(correct_credentials):
    credentials[usernames[i]] = {'password': passwords[i], 'phone': phones[i]}


@pytest.fixture
def client():
    application.app.config['TESTING'] = True
    application.app.config['WTF_CSRF_CHECK_DEFAULT'] = False
    application.app.config['WTF_CSRF_ENABLED'] = False
    with application.app.test_client() as client:
        with application.app.app_context():
            s = application.app
            c = application.app.app_context()
        yield client


def register(client, username, password, phone=''):
    return client.post('/register', data={'username': username, 'password': password, 'phone': phone},
                       follow_redirects=True)


def login(client, username, password='', phone=''):
    return client.post('/login', data={'username': username, 'password': password, 'phone': phone},
                       follow_redirects=True)


def spell_check(client, input):
    return client.post('/spell_check', data={'input': input}, follow_redirects=True)


def test_register_get(client):
    response = client.get('/register')
    assert response.status_code == 200
    assert b"User Registration" in response.data


def test_register_post(client):
    #valid username, password, phone
    response = register(client, usernames[0], passwords[0], phones[0])
    assert b'Success! You have been registered.' in response.data
    assert b'Click' in response.data
    assert b'to log in.' in response.data

    #valid username, password
    response = register(client=client, username=usernames[1], password=passwords[1])
    assert b'Success! You have been registered.' in response.data
    assert b'Click' in response.data
    assert b'to log in.' in response.data

    #duplicate username
    response = register(client=client, username=usernames[0].lower(), password=passwords[3])
    assert b'Username already taken. Please choose another one.' in response.data

    #duplicate uppercase username
    response = register(client=client, username=usernames[0].upper(), password=passwords[3])
    assert b'Only lowercase letters and numbers allowed.' in response.data

    #invalid username - not alphanumeric, too short
    response = register(client=client, username=usernames[4], password=passwords[3])
    assert b'Invalid username.' in response.data
    assert b'Only lowercase letters and numbers allowed.' in response.data
    assert b'Must be between 8 and 32 characters long.' in response.data

    # invalid username - too long
    response = register(client=client, username=usernames[4], password=passwords[4])
    assert b'Invalid username.' in response.data
    assert b'Must be between 8 and 32 characters long.' in response.data

    #invalid password - has other special characters
    response = register(client=client, username=usernames[2], password=passwords[4])
    assert b'Invalid password.' in response.data
    message = escape('Only letters, numbers, and the following special characters: _, @, #, %, and * allowed.').encode()
    assert message in response.data

    #invalid password - too long
    response = register(client=client, username=usernames[2], password=passwords[5])
    assert b'Invalid password.' in response.data
    assert b'Must be between 8 and 32 characters long.' in response.data

    # invalid password - only special characters but too short
    response = register(client=client, username=usernames[2], password=passwords[5])
    assert b'Invalid password.' in response.data
    assert b'Must be between 8 and 32 characters long.' in response.data

    #invalid phone - too long
    response = register(client=client, username=usernames[2], password=passwords[2], phone=phones[4])
    assert b'Invalid phone number' in response.data
    assert b'Only digits allowed and must be 10 digits long.' in response.data

    #invalid phone - too short
    response = register(client=client, username=usernames[2], password=passwords[2], phone=phones[5])
    assert b'Invalid phone number' in response.data
    assert b'Only digits allowed and must be 10 digits long.' in response.data

    #invalid phone - starts with a 0
    response = register(client=client, username=usernames[2], password=passwords[2], phone=phones[6])
    assert b'Invalid phone number' in response.data
    assert b'Only digits allowed and must be 10 digits long.' in response.data

    #invalid phone - alphanumeric
    response = register(client=client, username=usernames[2], password=passwords[2], phone=phones[7])
    assert b'Only digits allowed and must be 10 digits long.' in response.data


def test_login_get(client):
    response = client.get('/login')
    assert response.status_code == 200
    assert b'Sign in below or' in response.data
    assert b'for a new account' in response.data


def test_login_post_success(client):
    #correct username, password, phone
    register(client, username=usernames[0], password=passwords[0], phone=phones[0])
    response = login(client=client, username=usernames[0], password=passwords[0], phone=phones[0])
    assert b'Success! You have been logged in.' in response.data
    assert b'Click' in response.data
    assert b'to access the spell checker.' in response.data

    #correct username and phone
    response = login(client=client, username=usernames[0], phone=phones[0])
    assert b'Success! You have been logged in.' in response.data
    assert b'Click' in response.data
    assert b'to access the spell checker.' in response.data

    #correct username, phone, incorrect password
    response = login(client=client, username=usernames[0], password=passwords[1], phone=phones[0])
    assert b'Success! You have been logged in.' in response.data
    assert b'Click' in response.data
    assert b'to access the spell checker.' in response.data

    #correct username, password, incorrect phone
    response = login(client=client, username=usernames[0], password=passwords[0], phone=phones[1])
    assert b'Success! You have been logged in.' in response.data
    assert b'Click' in response.data
    assert b'to access the spell checker.' in response.data


def test_login_post_failure(client):
    #nonregistered user
    response = login(client=client, username=usernames[3], password=passwords[3])
    assert b'Incorrect username, password, and/or phone. Please try again.' in response.data

    #incorrect password
    response = login(client=client, username=usernames[0], password=passwords[1])
    assert b'Incorrect username, password, and/or phone. Please try again.' in response.data

    #incorrect phone
    response = login(client=client, username=usernames[0], phone=phones[1])
    assert b'Two-factor authentication failure.' in response.data


def test_spell_check_get_before_log_in(client):
    response = client.get('/spell_check', follow_redirects=True)
    assert b'You must be logged in to view this page.' in response.data


def test_spell_check_get_after_log_in(client):
    register(client, username=usernames[0], password=passwords[0], phone=phones[0])
    login(client, username=usernames[0], password=passwords[0], phone=phones[0])
    response = client.get('/spell_check', follow_redirects=True)
    assert b'Spell Check' in response.data
    assert b'Enter text to be spell checked.' in response.data
    assert ('You are logged in as ' + usernames[0] + '.').encode()


def test_spell_check_post(client):
    login(client, username=usernames[0], password=passwords[0], phone=phones[0])

    #valid input
    input = 'Take a sad sogn and make it better. Remember to let her under your skyn, then you begin to make it betta.'
    response = spell_check(client, input)
    assert b'Spell Check' in response.data
    assert b'Enter text to be spell checked.' in response.data
    assert ('You are logged in as ' + usernames[0] + '.').encode() in response.data
    assert ('Input text: ' + input).encode() in response.data
    assert b'The following 3 words were misspelled:' in response.data
    assert b'sogn' in response.data
    assert b'skyn' in response.data
    assert b'betta' in response.data

    #escaped input
    input = '<>!@#$%!@#$'
    response = spell_check(client, input)
    print(response.data)
    assert b'Spell Check' in response.data
    assert b'Enter text to be spell checked.' in response.data
    assert ('You are logged in as ' + usernames[0] + '.').encode() in response.data
    assert b'Input text: &amp;lt;&amp;gt;!@#$%!@#$' in response.data
    assert b'The following 1 words were misspelled:' in response.data
    assert b'lt;&amp;gt' in response.data

    #invalid input
    input = '<><><><>>'
    response = spell_check(client, input)
    assert b'Spell Check' in response.data
    assert b'Enter text to be spell checked.' in response.data
    assert ('You are logged in as ' + usernames[0] + '.').encode() in response.data
    assert b'Input text: &amp;lt;&amp;gt;&amp;lt;&amp;gt;&amp;lt;&amp;gt;&amp;lt;&amp;gt;&amp;gt;' in response.data
    assert b'Could not spell check invalid input.' in response.data

    #input too long
    input = "i'm trying to overflow the input buffer, which a hacker might do as part of a denial of service (DOS) attack, " \
            "but i'm a step ahead of them"
    response = spell_check(client, input)
    assert b'Spell Check' in response.data
    assert b'Enter text to be spell checked.' in response.data
    assert ('You are logged in as ' + usernames[0] + '.').encode() in response.data
    assert b'Input cannot be longer than 128 characters' in response.data


def test_logout(client):
    register(client, usernames[0], passwords[0], phones[0])
    login(client, usernames[0], passwords[0], phones[0])
    response = client.post('/logout', follow_redirects=True)
    assert b'You have been logged out.' in response.data


