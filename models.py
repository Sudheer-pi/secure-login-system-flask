from datetime import datetime, timezone, timedelta
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
import bcrypt

# Initialize the SQLAlchemy instance to be bound in app.py
db = SQLAlchemy()

class User(db.Model, UserMixin):
    """Database model for application users, featuring secure credentials, lockout status, and 2FA secrets."""
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default='user', nullable=False)  # 'user' or 'admin'
    is_active = db.Column(db.Boolean, default=True, nullable=False)   # Account status management
    
    # Brute Force Protection / Lockout properties
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    lockout_until = db.Column(db.DateTime, nullable=True)
    
    # 2FA credentials
    two_factor_secret = db.Column(db.String(32), nullable=True)
    two_factor_enabled = db.Column(db.Boolean, default=False, nullable=False)
    
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None), nullable=False)

    # Relationships
    login_logs = db.relationship('LoginHistory', backref='user', lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        """Salt and hash password using BCrypt with secure work factor (12 rounds)."""
        # Bcrypt requires bytes for input. We encode the password string to UTF-8
        password_bytes = password.encode('utf-8')
        salt = bcrypt.gensalt(rounds=12)
        hashed_bytes = bcrypt.hashpw(password_bytes, salt)
        # Store the hash as a string in the database
        self.password_hash = hashed_bytes.decode('utf-8')

    def check_password(self, password):
        """Compare a plaintext password with the stored BCrypt hash."""
        if not self.password_hash:
            return False
        try:
            return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
        except Exception:
            return False

    def is_locked_out(self):
        """Checks if the user account is currently under lockout restriction."""
        if self.lockout_until:
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            if now < self.lockout_until:
                return True
            else:
                # Lockout duration has expired, reset status automatically
                self.reset_failed_attempts()
                db.session.commit()
        return False

    def time_remaining_lockout(self):
        """Returns remaining seconds of the lockout duration."""
        if not self.lockout_until:
            return 0
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        remaining = (self.lockout_until - now).total_seconds()
        return max(0, int(remaining))

    def increment_failed_attempts(self, max_attempts=5, lockout_minutes=10):
        """Increments failed logins; if limit hit, locks the account for the specified minutes."""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= max_attempts:
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            self.lockout_until = now + timedelta(minutes=lockout_minutes)
        db.session.commit()

    def reset_failed_attempts(self):
        """Resets failed login counters and clears account lock status."""
        self.failed_login_attempts = 0
        self.lockout_until = None
        db.session.commit()


class LoginHistory(db.Model):
    """Model for logging all successful and failed authentication attempts for security auditing."""
    __tablename__ = 'login_history'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=True)
    username_attempted = db.Column(db.String(50), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)  # Supports both IPv4 and IPv6
    user_agent = db.Column(db.String(250), nullable=False)
    
    # Status codes: 'SUCCESS', 'FAILED_CREDENTIALS', 'FAILED_LOCKOUT', 'FAILED_INACTIVE', 'FAILED_2FA'
    status = db.Column(db.String(30), nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None), nullable=False)
