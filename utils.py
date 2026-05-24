import os
import re
import io
import base64
import logging
from logging.handlers import RotatingFileHandler
from functools import wraps
from flask import request, redirect, url_for, flash, abort
from flask_login import current_user
import qrcode

def setup_logger():
    """Initializes and returns a rotating security logger for authentication audits."""
    base_dir = os.path.abspath(os.path.dirname(__file__))
    log_dir = os.path.join(base_dir, 'logs')
    
    # Ensure logs folder exists
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
        
    log_file = os.path.join(log_dir, 'auth.log')
    
    # Setup standard logger
    logger = logging.getLogger('secure_auth_audit')
    logger.setLevel(logging.INFO)
    
    # Avoid adding duplicate handlers if logger is already configured
    if not logger.handlers:
        # Limit files to 5MB, keep 5 backups
        file_handler = RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=5)
        formatter = logging.Formatter(
            '[%(asctime)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S %z'
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        # Also print to terminal for visibility
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
    return logger

# Globally accessible logger instance
audit_logger = setup_logger()

def log_security_event(event_type, username, status, details=""):
    """
    Standardized formatting of security logs.
    Captures remote IP, client user-agent, username, and specific status codes.
    """
    ip = request.remote_addr or 'Unknown'
    # Check for X-Forwarded-For if behind a proxy
    if request.headers.get('X-Forwarded-For'):
        ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
        
    user_agent = request.headers.get('User-Agent', 'Unknown')
    log_msg = f"[EVENT: {event_type}] [STATUS: {status}] [USER: {username}] [IP: {ip}] [UA: {user_agent}] - {details}"
    
    if status == 'FAIL' or status == 'LOCKED' or status == 'SUSPICIOUS':
        audit_logger.warning(log_msg)
    else:
        audit_logger.info(log_msg)

def is_password_strong(password):
    """
    Validates password strength according to strict cybersecurity guidelines:
    - Minimum 12 characters long
    - At least one uppercase letter [A-Z]
    - At least one lowercase letter [a-z]
    - At least one number [0-9]
    - At least one special symbol [!@#$%^&*(),.?\":{}|<>]
    """
    if len(password) < 12:
        return False, "Password must be at least 12 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter (A-Z)."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter (a-z)."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one numeric digit (0-9)."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>\-_=+\[\]{};:'`~\\/]", password):
        return False, "Password must contain at least one special character (e.g. !@#$%^&*)."
    return True, "Password is strong and compliant."

def generate_totp_qr_base64(username, secret, issuer_name="SecureSentinel"):
    """
    Generates a secure QR code in memory as a base64 string.
    Ensures 2FA keys never touch physical disk storage.
    """
    # Clean username to avoid injection into QR URI scheme
    clean_username = re.sub(r'[^a-zA-Z0-9@._\-]', '', username)
    totp_uri = f"otpauth://totp/{issuer_name}:{clean_username}?secret={secret}&issuer={issuer_name}"
    
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=6,
        border=3
    )
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    # Render QR code using high contrast theme styling
    img = qr.make_image(fill_color="#00f2fe", back_color="#0a0b0d")
    
    buffered = io.BytesIO()
    try:
        img.save(buffered, format="PNG")
    except TypeError:
        # Secure fallback for PyPNGImage backend (does not accept the 'format' keyword)
        img.save(buffered)
        
    return base64.b64encode(buffered.getvalue()).decode('utf-8')

def admin_required(f):
    """Decorator to enforce that the logged-in user has administrative clearance."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        if current_user.role != 'admin':
            log_security_event('UNAUTHORIZED_ACCESS', current_user.username, 'FAIL', f"Attempted to access admin page: {request.path}")
            flash("Access Denied: Administrative credentials required.", "danger")
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def anonymous_required(f):
    """Decorator to restrict access to authenticated users (e.g., redirecting to dashboard)."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function
