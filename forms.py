from flask_wtf import Form
from wtforms import StringField, PasswordField, IntegerField, SubmitField, TextAreaField
from wtforms.validators import InputRequired, Length, NumberRange, Optional, Regexp

MIN_CREDENTIAL_LENGTH = 8
MAX_CREDENTIAL_LENGTH = 32
PHONE_LENGTH = 10
MIN_PHONE_VALUE = 1000000000
MAX_PHONE_VALUE = 9999999999
MAX_INPUT_LENGTH = 128

USERNAME_REGEX_VALIDATOR = Regexp(regex="^[a-z0-9*]+$",
                                              message="Username can only contain lowercase letters and numbers.")
USERNAME_LENGTH_VALIDATOR = Length(MIN_CREDENTIAL_LENGTH, MAX_CREDENTIAL_LENGTH,
                                   "Username must be between 8 and 32 characters.")
PASSWORD_REGEX_VALIDATOR = Regexp(regex="^[a-zA-Z0-9_!@#$%&*]+$",
                                                message="Password can only contain letters, numbers, and the following special characters: _, !, @, #, $, %, &.")
PASSWORD_LENGTH_VALIDATOR = Length(MIN_CREDENTIAL_LENGTH, MAX_CREDENTIAL_LENGTH, "Password must be between 8 and 32 characters.")
PHONE_RANGE_VALIDATOR = NumberRange(MIN_PHONE_VALUE, MAX_PHONE_VALUE, "Invalid phone number.")

USERNAME_VALIDATORS = [InputRequired(), USERNAME_REGEX_VALIDATOR, USERNAME_LENGTH_VALIDATOR]
PASSWORD_VALIDATORS = [PASSWORD_REGEX_VALIDATOR, PASSWORD_LENGTH_VALIDATOR]
PHONE_VALIDATORS = [Optional(), PHONE_RANGE_VALIDATOR]
INPUT_VALIDATORS = [InputRequired(), Length(0, MAX_INPUT_LENGTH, "Input cannot be longer than 128 characters")]


class Registration(Form):
    PASSWORD_VALIDATORS.append(InputRequired())
    username = StringField('Username',validators=USERNAME_VALIDATORS)
    password = PasswordField('Password', validators=PASSWORD_VALIDATORS)
    phone = IntegerField('2fa', validators=PHONE_VALIDATORS)
    register = SubmitField()


class Login(Form):
    PASSWORD_VALIDATORS.append(Optional())
    username = StringField('Username', validators=USERNAME_VALIDATORS)
    password = PasswordField('Password', validators=PASSWORD_VALIDATORS)
    phone = IntegerField('2fa', validators=PHONE_VALIDATORS)
    sign_in = SubmitField()


class SpellCheck(Form):
    input = TextAreaField('Input', validators=INPUT_VALIDATORS)
    submit = SubmitField()