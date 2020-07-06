from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, IntegerField, SubmitField, TextAreaField
from wtforms.validators import InputRequired, Length, NumberRange, Optional, Regexp

MIN_CREDENTIAL_LENGTH = 8
MAX_CREDENTIAL_LENGTH = 32
PHONE_LENGTH = 10
MIN_PHONE_VALUE = 1000000000
MAX_PHONE_VALUE = 9999999999
MAX_INPUT_LENGTH = 128

USERNAME_REGEX_VALIDATOR = Regexp(regex="^[a-z0-9*]+$",
                                              message="Only lowercase letters and numbers allowed.")
USERNAME_LENGTH_VALIDATOR = Length(MIN_CREDENTIAL_LENGTH, MAX_CREDENTIAL_LENGTH,
                                   "Must be between 8 and 32 characters long.")
PASSWORD_REGEX_VALIDATOR = Regexp(regex="^[a-zA-Z0-9_!@#$%&*]+$",
                                                message="Only letters, numbers, and the following special characters: "
                                                        "_, !, @, #, $, %, &, and * allowed.")
PASSWORD_LENGTH_VALIDATOR = Length(MIN_CREDENTIAL_LENGTH, MAX_CREDENTIAL_LENGTH,
                                   "Must be between 8 and 32 characters long.")
PHONE_RANGE_VALIDATOR = NumberRange(MIN_PHONE_VALUE, MAX_PHONE_VALUE, "Only digits allowed and must be 10 digits long.")
USERNAME_VALIDATORS = [InputRequired(), USERNAME_REGEX_VALIDATOR, USERNAME_LENGTH_VALIDATOR]
PASSWORD_VALIDATORS = [PASSWORD_REGEX_VALIDATOR, PASSWORD_LENGTH_VALIDATOR]
PHONE_VALIDATORS = [Optional(), PHONE_RANGE_VALIDATOR]
INPUT_VALIDATORS = [InputRequired(), Length(0, MAX_INPUT_LENGTH, "Input cannot be longer than 128 characters.")]


class Registration(FlaskForm):
    registration_password_validators = [InputRequired()]
    registration_password_validators.extend(PASSWORD_VALIDATORS)
    username = StringField('Username: ', validators=USERNAME_VALIDATORS)
    password = PasswordField('Password: ', validators=registration_password_validators)
    phone = IntegerField('Phone (XXXXXXXXXX): ', validators=PHONE_VALIDATORS)
    register = SubmitField()


class Login(FlaskForm):
    login_password_validators = [Optional()]
    login_password_validators.extend(PASSWORD_VALIDATORS)
    username = StringField('Username: ', validators=USERNAME_VALIDATORS)
    password = PasswordField('Password: ', validators=login_password_validators)
    phone = IntegerField('Phone (XXXXXXXXXX): ', validators=PHONE_VALIDATORS)
    sign_in = SubmitField()


class SpellCheck(FlaskForm):
    input = TextAreaField('Input', validators=INPUT_VALIDATORS)
    submit = SubmitField()
    logout = SubmitField()