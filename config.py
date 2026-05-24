import os
from datetime import timedelta
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """Base configuration settings loaded from environment variables."""
    
    # Core Flask Configuration
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', os.urandom(32).hex())
    WTF_CSRF_SECRET_KEY = os.environ.get('WTF_CSRF_SECRET_KEY', os.urandom(32).hex())
    
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    
    # Flask-SQLAlchemy Configuration
    # We resolve the relative SQLite URI into an absolute path to prevent working directory issues
    _db_uri = os.environ.get('DATABASE_URL', 'sqlite:///database/secure_login.db')
    if _db_uri.startswith('sqlite:///'):
        _rel_path = _db_uri.replace('sqlite:///', '').lstrip('/')
        _abs_path = os.path.abspath(os.path.join(BASE_DIR, _rel_path))
        # Ensure parent folder exists
        os.makedirs(os.path.dirname(_abs_path), exist_ok=True)
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{_abs_path}"
    else:
        SQLALCHEMY_DATABASE_URI = _db_uri
        
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Session Management & Hardening
    # Enforces HTTPS for cookies. Fallback to False only if explicitly in development and running on HTTP.
    SESSION_COOKIE_SECURE = os.environ.get('FLASK_ENV') != 'development'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Auto-logout session duration
    SESSION_TIMEOUT_MINUTES = int(os.environ.get('SESSION_TIMEOUT_MINUTES', 15))
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=SESSION_TIMEOUT_MINUTES)
    
    # Account lockout configuration
    LOCKOUT_ATTEMPTS = int(os.environ.get('LOCKOUT_ATTEMPTS', 5))
    LOCKOUT_MINUTES = int(os.environ.get('LOCKOUT_MINUTES', 10))
    
    # Rate Limiting configuration
    AUTH_RATE_LIMIT = os.environ.get('AUTH_RATE_LIMIT', '5 per minute')
    GLOBAL_RATE_LIMIT = os.environ.get('GLOBAL_RATE_LIMIT', '60 per minute')
    
    # Absolute paths for logs and database to avoid working directory errors
    LOG_FILE_PATH = os.path.join(BASE_DIR, 'logs', 'auth.log')
    DB_FILE_PATH = os.path.join(BASE_DIR, 'database', 'secure_login.db')
