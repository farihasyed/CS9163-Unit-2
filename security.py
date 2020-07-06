from flask import session, request

service_referrer = {'login': ['login', 'spell_check', 'register'], 'register': ['login', 'register', 'spell_check'],
                    'spell_check': ['login', 'spell_check', 'register'], 'logout': ['spell_check']}
session_token = {}


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


def check_user():
    user = session['user']
    expected = session_token[user['username']]
    remote_address = request.remote_addr
    return remote_address == expected['remote address'] == user['remote address'] and user['token'] == expected['token'] and check_referrer()


def check_referrer():
    service = request.endpoint
    remote_address = request.remote_addr
    referrer = request.referrer
    if service in service_referrer:
        if referrer is None:
            return True
        for ref in service_referrer[service]:
            referrer.find(ref)
            if referrer.find(remote_address) != -1 and referrer.find(ref) != -1:
                return True
    return False