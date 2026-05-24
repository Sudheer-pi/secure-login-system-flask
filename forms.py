from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SelectField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError, Regexp
from models import User
from utils import is_password_strong

class LoginForm(FlaskForm):
    """Secure authentication input form protecting against empty data and CSRF."""
    username_or_email = StringField('Username or Email', validators=[
        DataRequired(message="Username or email is required."),
        Length(max=120)
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required.")
    ])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')


class RegistrationForm(FlaskForm):
    """Secure user registration form enforcing password complexity and unique constraint checks."""
    username = StringField('Username', validators=[
        DataRequired(message="Username is required."),
        Length(min=3, max=50, message="Username must be between 3 and 50 characters."),
        Regexp(r'^[a-zA-Z0-9_\-\.]+$', message="Username can only contain alphanumeric characters, underscores, hyphens, and dots.")
    ])
    email = StringField('Email Address', validators=[
        DataRequired(message="Email address is required."),
        Email(message="Invalid email address format."),
        Length(max=120, message="Email must be under 120 characters.")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required.")
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(message="Password confirmation is required."),
        EqualTo('password', message="Password confirmation must match original password.")
    ])
    submit = SubmitField('Create Account')

    def validate_username(self, username):
        """Proactively checks if the username is already registered."""
        # Sanitize check against database lookup
        user = User.query.filter_by(username=username.data.strip()).first()
        if user:
            raise ValidationError("This username is already registered. Please select another.")

    def validate_email(self, email):
        """Proactively checks if the email is already registered."""
        # Sanitize check against database lookup
        user = User.query.filter_by(email=email.data.strip().lower()).first()
        if user:
            raise ValidationError("This email is already registered. Please log in or use a different email.")

    def validate_password(self, password):
        """Validates password against our security password complexity checker helper."""
        is_strong, reason = is_password_strong(password.data)
        if not is_strong:
            raise ValidationError(reason)


class TwoFactorForm(FlaskForm):
    """Input form for 2FA Time-based One-Time Password validation."""
    otp_code = StringField('One-Time Passcode (6-Digit)', validators=[
        DataRequired(message="OTP code is required."),
        Length(min=6, max=6, message="Passcode must be exactly 6 digits."),
        Regexp(r'^\d{6}$', message="Passcode must contain digits only.")
    ])
    submit = SubmitField('Verify Code')


class ChangePasswordForm(FlaskForm):
    """Secure form to change passwords, validating strong password requirements."""
    current_password = PasswordField('Current Password', validators=[
        DataRequired(message="Current password is required.")
    ])
    new_password = PasswordField('New Password', validators=[
        DataRequired(message="New password is required.")
    ])
    confirm_new_password = PasswordField('Confirm New Password', validators=[
        DataRequired(message="Please confirm your new password."),
        EqualTo('new_password', message="New password confirmation must match.")
    ])
    submit = SubmitField('Update Password')

    def validate_new_password(self, new_password):
        """Enforces complexity on the new password choice."""
        is_strong, reason = is_password_strong(new_password.data)
        if not is_strong:
            raise ValidationError(reason)


class AdminUserEditForm(FlaskForm):
    """Form used inside the Admin Dashboard to manage roles and enable/disable states."""
    role = SelectField('User Role', choices=[('user', 'Standard User'), ('admin', 'System Admin')], validators=[DataRequired()])
    status = SelectField('Account Status', choices=[('active', 'Active'), ('disabled', 'Disabled')], validators=[DataRequired()])
    submit = SubmitField('Save Account Configuration')
