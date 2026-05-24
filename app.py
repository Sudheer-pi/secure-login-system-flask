from datetime import datetime, timezone
import os
import pyotp
from flask import Flask, render_template, redirect, url_for, flash, request, session, abort
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Import custom modules
from config import Config
from models import db, User, LoginHistory
from forms import LoginForm, RegistrationForm, TwoFactorForm, ChangePasswordForm
from utils import log_security_event, admin_required, anonymous_required, generate_totp_qr_base64

# Instantiate Flask application
app = Flask(__name__)
app.config.from_object(Config)

# Enable automatic session renewal on every request to accurately implement inactivity timeout
app.config['SESSION_REFRESH_EACH_REQUEST'] = True

# Initialize database
db.init_app(app)

# Initialize Global CSRF protection
csrf = CSRFProtect(app)

# Initialize Flask-Limiter for brute force defense
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[app.config.get('GLOBAL_RATE_LIMIT', "60 per minute")]
)

# Initialize Flask-Login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Access restricted: Please authenticate first."
login_manager.login_message_category = "warning"

@login_manager.user_loader
def load_user(user_id):
    """Callback to load User object by key from session."""
    return User.query.get(int(user_id))

# --- Global Security Headers Middleware ---
@app.after_request
def inject_security_headers(response):
    """Enforces strict browser security rules on every response via headers."""
    # CSP: Allow self files, inline CSS/JS safety, Google Fonts, base64 data for QR images, and CDNs for fallback styling
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; "
        "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "frame-ancestors 'none';"
    )
    # Anti-Clickjacking
    response.headers['X-Frame-Options'] = 'DENY'
    # Anti-MIME-sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Control referral leakages
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    # Lock down device hardware access
    response.headers['Permissions-Policy'] = 'geolocation=(), camera=(), microphone=()'
    
    # Enforce SSL when not debugging locally
    if not app.config['DEBUG']:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        
    return response

# --- Custom Inactivity Timeout Handler ---
@app.before_request
def verify_session_lifetime():
    """Validates session inactivity timeouts. Emits security audit events on timeouts."""
    if current_user.is_authenticated:
        session.permanent = True
        # Read permanent session lifetime configuration
        lifetime = app.permanent_session_lifetime
        
        # Check last active timestamp
        last_activity = session.get('last_activity')
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        
        if last_activity:
            try:
                # Convert string ISO format back to naive datetime
                last_active_dt = datetime.fromisoformat(last_activity)
                if now - last_active_dt > lifetime:
                    log_security_event('SESSION_TIMEOUT', current_user.username, 'SUCCESS', "Session expired due to user inactivity.")
                    logout_user()
                    session.clear()
                    flash("Your session has expired due to inactivity. Please log in again.", "warning")
                    return redirect(url_for('login'))
            except Exception:
                pass
        
        # Update current activity timestamp
        session['last_activity'] = now.isoformat()

# --- Exception Error Route Handlers ---
@app.errorhandler(404)
def page_not_found(e):
    return render_template('base.html', title="404 - Not Found", error_code=404, error_msg="The resource you requested could not be located."), 404

@app.errorhandler(403)
def access_denied(e):
    return render_template('base.html', title="403 - Forbidden", error_code=403, error_msg="You do not possess the clearance level required to view this sector."), 403

@app.errorhandler(500)
def server_error(e):
    return render_template('base.html', title="500 - Internal Error", error_code=500, error_msg="An internal systems anomaly has occurred. Administrators have been notified."), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    """Custom response for rate limiter triggers to mitigate scraping and brute forcing."""
    log_security_event('RATE_LIMIT_TRIGGERED', 'anonymous', 'FAIL', f"IP triggered rate limiting on: {request.path}")
    return render_template('base.html', title="429 - Throttled", error_code=429, error_msg="Systems detect anomalous traffic. Rate limit exceeded. Please stand by before retrying."), 429

# --- Application Routing ---

@app.route('/')
def index():
    """Root route redirecting based on authentication state."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
@anonymous_required
@limiter.limit(Config.AUTH_RATE_LIMIT)
def register():
    """Handles secure user sign-up, validates strength requirements, and prevents duplicate registration."""
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        email = form.email.data.strip().lower()
        
        # Instantiate new user
        new_user = User(
            username=username,
            email=email,
            role='user',
            is_active=True
        )
        # Salt and hash password using BCrypt
        new_user.set_password(form.password.data)
        
        db.session.add(new_user)
        db.session.commit()
        
        log_security_event('USER_REGISTRATION', username, 'SUCCESS', f"Account registered with email: {email}")
        flash("Registration successful! You may now authenticate.", "success")
        return redirect(url_for('login'))
        
    return render_template('register.html', title="Secure Sign-Up", form=form)

@app.route('/login', methods=['GET', 'POST'])
@anonymous_required
@limiter.limit(Config.AUTH_RATE_LIMIT)
def login():
    """
    Handles user authentication.
    Applies account lockout checks, increments failed counters, and triggers the 2FA flow if enabled.
    """
    form = LoginForm()
    if form.validate_on_submit():
        username_or_email = form.username_or_email.data.strip()
        password = form.password.data
        
        # Multi-factor credential lookup (supports Username or Email)
        user = User.query.filter((User.username == username_or_email) | (User.email == username_or_email.lower())).first()
        
        if not user:
            # Defensive logging to block username enumeration vectors
            log_security_event('AUTH_ATTEMPT', username_or_email, 'FAIL', "Invalid credentials (user not found).")
            flash("Invalid username/email or password.", "danger")
            return redirect(url_for('login'))
            
        # 1. Lockout Check
        if user.is_locked_out():
            log_security_event('AUTH_ATTEMPT', user.username, 'LOCKED', f"Blocked attempt on locked account. Lock remaining: {user.time_remaining_lockout()} seconds.")
            flash(f"This account is temporarily locked due to excessive failed attempts. Please try again in {user.time_remaining_lockout() // 60 + 1} minutes.", "danger")
            return redirect(url_for('login'))
            
        # 2. Status Check
        if not user.is_active:
            log_security_event('AUTH_ATTEMPT', user.username, 'FAIL', "Blocked login on disabled account.")
            flash("This account is currently deactivated. Please contact support.", "danger")
            return redirect(url_for('login'))
            
        # 3. Password Verification
        if not user.check_password(password):
            user.increment_failed_attempts(max_attempts=Config.LOCKOUT_ATTEMPTS, lockout_minutes=Config.LOCKOUT_MINUTES)
            
            # Formulate audit details
            rem = Config.LOCKOUT_ATTEMPTS - user.failed_login_attempts
            details = f"Incorrect password. Failed attempts: {user.failed_login_attempts}/{Config.LOCKOUT_ATTEMPTS}."
            if user.failed_login_attempts >= Config.LOCKOUT_ATTEMPTS:
                details += f" Account locked for {Config.LOCKOUT_MINUTES} minutes."
                log_security_event('ACCOUNT_LOCKOUT', user.username, 'LOCKED', details)
                flash(f"Account locked! Excess failures. Please try again in {Config.LOCKOUT_MINUTES} minutes.", "danger")
            else:
                log_security_event('AUTH_ATTEMPT', user.username, 'FAIL', details)
                flash("Invalid username/email or password.", "danger")
            
            # Record failed log to db history
            failed_log = LoginHistory(
                user_id=user.id,
                username_attempted=user.username,
                ip_address=request.remote_addr or 'Unknown',
                user_agent=request.headers.get('User-Agent', 'Unknown'),
                status='FAILED_CREDENTIALS'
            )
            db.session.add(failed_log)
            db.session.commit()
            return redirect(url_for('login'))
            
        # Reset failed login count on password success
        user.reset_failed_attempts()
        
        # 4. Two-Factor Authentication Check
        if user.two_factor_enabled:
            # Set intermediate session token instead of logging in directly
            session['pre_2fa_user_id'] = user.id
            session['remember_me'] = form.remember_me.data
            log_security_event('AUTH_STEP_1', user.username, 'SUCCESS', "Step 1 primary auth success. Redirecting to 2FA verification.")
            return redirect(url_for('login_2fa'))
            
        # 5. Direct login if 2FA is inactive
        login_user(user, remember=form.remember_me.data)
        
        # Record success to database
        success_log = LoginHistory(
            user_id=user.id,
            username_attempted=user.username,
            ip_address=request.remote_addr or 'Unknown',
            user_agent=request.headers.get('User-Agent', 'Unknown'),
            status='SUCCESS'
        )
        db.session.add(success_log)
        db.session.commit()
        
        log_security_event('AUTH_LOGIN', user.username, 'SUCCESS', "User authenticated successfully.")
        flash(f"Welcome back, {user.username}!", "success")
        return redirect(url_for('dashboard'))
        
    return render_template('login.html', title="Secure Authentication", form=form)

@app.route('/login/2fa', methods=['GET', 'POST'])
@anonymous_required
@limiter.limit(Config.AUTH_RATE_LIMIT)
def login_2fa():
    """Enforces Time-based One-Time Passwords verification before finalizing system sessions."""
    pre_user_id = session.get('pre_2fa_user_id')
    if not pre_user_id:
        return redirect(url_for('login'))
        
    user = User.query.get(pre_user_id)
    if not user or not user.two_factor_enabled:
        session.pop('pre_2fa_user_id', None)
        return redirect(url_for('login'))
        
    form = TwoFactorForm()
    if form.validate_on_submit():
        otp_code = form.otp_code.data.strip()
        
        # Verify using PyOTP TOTP module
        totp = pyotp.TOTP(user.two_factor_secret)
        if totp.verify(otp_code, valid_window=1): # Allow a small drift window (30s before/after)
            # Authenticate fully
            login_user(user, remember=session.pop('remember_me', False))
            session.pop('pre_2fa_user_id', None)
            
            # Log success
            success_log = LoginHistory(
                user_id=user.id,
                username_attempted=user.username,
                ip_address=request.remote_addr or 'Unknown',
                user_agent=request.headers.get('User-Agent', 'Unknown'),
                status='SUCCESS'
            )
            db.session.add(success_log)
            db.session.commit()
            
            log_security_event('AUTH_LOGIN_2FA', user.username, 'SUCCESS', "2FA verification succeeded. User authenticated.")
            flash(f"2FA Authenticated. Welcome, {user.username}!", "success")
            return redirect(url_for('dashboard'))
        else:
            log_security_event('AUTH_LOGIN_2FA', user.username, 'FAIL', "Failed 2FA verification attempt.")
            flash("Invalid verification passcode. Please try again.", "danger")
            
            # Record failed log to db history
            failed_log = LoginHistory(
                user_id=user.id,
                username_attempted=user.username,
                ip_address=request.remote_addr or 'Unknown',
                user_agent=request.headers.get('User-Agent', 'Unknown'),
                status='FAILED_2FA'
            )
            db.session.add(failed_log)
            db.session.commit()
            
    return render_template('login_2fa.html', title="2FA Validation", form=form)

@app.route('/logout')
@login_required
def logout():
    """Signs out current session, purges cookies, and logs the event."""
    username = current_user.username
    logout_user()
    session.clear()
    log_security_event('AUTH_LOGOUT', username, 'SUCCESS', "User signed out.")
    flash("You have logged out successfully.", "info")
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Renders user metrics, dashboard controls, active security alerts, and handles 2FA configuration."""
    # Retrieve last 10 security logs for this specific user
    user_logs = LoginHistory.query.filter_by(user_id=current_user.id).order_by(LoginHistory.timestamp.desc()).limit(10).all()
    
    # 2FA setup stage variables
    qr_code_data = None
    temp_secret = None
    
    if not current_user.two_factor_enabled:
        # Check if secret already cached for this flow, otherwise initialize secure key
        temp_secret = session.get('temp_2fa_secret')
        if not temp_secret:
            temp_secret = pyotp.random_base32()
            session['temp_2fa_secret'] = temp_secret
        
        # Build base64 display image for Google Authenticator scan
        qr_code_data = generate_totp_qr_base64(current_user.username, temp_secret)
        
    form = TwoFactorForm()
    
    return render_template(
        'dashboard.html', 
        title="Command Dashboard", 
        user_logs=user_logs,
        qr_code=qr_code_data,
        temp_secret=temp_secret,
        form=form
    )

@app.route('/dashboard/2fa/enable', methods=['POST'])
@login_required
def enable_2fa():
    """Validates the setup passcode and activates 2FA on the user's account."""
    form = TwoFactorForm()
    temp_secret = session.get('temp_2fa_secret')
    
    if not temp_secret or current_user.two_factor_enabled:
        flash("System error. Resetting 2FA setup sequence.", "danger")
        return redirect(url_for('dashboard'))
        
    if form.validate_on_submit():
        otp_code = form.otp_code.data.strip()
        totp = pyotp.TOTP(temp_secret)
        
        if totp.verify(otp_code, valid_window=1):
            # Finalize db model states
            current_user.two_factor_secret = temp_secret
            current_user.two_factor_enabled = True
            db.session.commit()
            
            # Clean temporary cache
            session.pop('temp_2fa_secret', None)
            
            log_security_event('2FA_ENABLED', current_user.username, 'SUCCESS', "2FA setup verified and enabled.")
            flash("Two-Factor Authentication (2FA) is now active on your account!", "success")
        else:
            log_security_event('2FA_ENABLE_ATTEMPT', current_user.username, 'FAIL', "Incorrect setup token entered during 2FA configuration.")
            flash("Invalid code. Please ensure your authenticator matches the secret and try again.", "danger")
            
    return redirect(url_for('dashboard'))

@app.route('/dashboard/2fa/disable', methods=['POST'])
@login_required
def disable_2fa():
    """Disables 2FA on user request, requiring a valid OTP token first."""
    form = TwoFactorForm()
    if form.validate_on_submit():
        otp_code = form.otp_code.data.strip()
        totp = pyotp.TOTP(current_user.two_factor_secret)
        
        if totp.verify(otp_code, valid_window=1):
            current_user.two_factor_secret = None
            current_user.two_factor_enabled = False
            db.session.commit()
            
            log_security_event('2FA_DISABLED', current_user.username, 'SUCCESS', "2FA disabled by user.")
            flash("Two-Factor Authentication (2FA) has been deactivated successfully.", "warning")
        else:
            log_security_event('2FA_DISABLE_ATTEMPT', current_user.username, 'FAIL', "Failed token verification while disabling 2FA.")
            flash("Verification failed. 2FA remains active.", "danger")
            
    return redirect(url_for('dashboard'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """Allows user to change password after verifying the existing password."""
    form = ChangePasswordForm()
    if form.validate_on_submit():
        current_pwd = form.current_password.data
        new_pwd = form.new_password.data
        
        # Verify current password
        if not current_user.check_password(current_pwd):
            log_security_event('PASSWORD_CHANGE', current_user.username, 'FAIL', "Invalid current password provided during password change.")
            flash("Incorrect current password. Action denied.", "danger")
            return redirect(url_for('profile'))
            
        # Prevent reuse of same password
        if current_user.check_password(new_pwd):
            flash("Your new password must be different from your current password.", "warning")
            return redirect(url_for('profile'))
            
        # Apply new hashed password
        current_user.set_password(new_pwd)
        db.session.commit()
        
        log_security_event('PASSWORD_CHANGE', current_user.username, 'SUCCESS', "Password changed successfully.")
        flash("Password updated successfully!", "success")
        return redirect(url_for('profile'))
        
    return render_template('profile.html', title="Account Profile", form=form)

# --- Administrative Dashboard Routes ---

@app.route('/admin')
@login_required
@admin_required
def admin():
    """Displays administration systems console: global audit trails and client account registries."""
    users = User.query.order_by(User.id.asc()).all()
    # Pull global login logs
    logs = LoginHistory.query.order_by(LoginHistory.timestamp.desc()).limit(100).all()
    
    # Calculate some quick stats
    total_users = len(users)
    active_users = sum(1 for u in users if u.is_active)
    locked_users = sum(1 for u in users if u.is_locked_out())
    failed_attempts_total = sum(1 for l in logs if l.status != 'SUCCESS')
    
    return render_template(
        'admin.html',
        title="Admin Security Operations Console",
        users=users,
        logs=logs,
        total_users=total_users,
        active_users=active_users,
        locked_users=locked_users,
        failed_attempts=failed_attempts_total
    )

@app.route('/admin/toggle-status/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def toggle_status(user_id):
    """Admin endpoint to activate/deactivate accounts."""
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("Security violation: You cannot disable your own administrative account.", "danger")
        return redirect(url_for('admin'))
        
    user.is_active = not user.is_active
    db.session.commit()
    
    status_str = "ENABLED" if user.is_active else "DISABLED"
    log_security_event('ADMIN_USER_STATUS_CHANGE', current_user.username, 'SUCCESS', f"User {user.username} was {status_str}.")
    flash(f"Account state of '{user.username}' is now set to {status_str}.", "success")
    return redirect(url_for('admin'))

@app.route('/admin/unlock-user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def unlock_user(user_id):
    """Admin endpoint to unlock locked out accounts."""
    user = User.query.get_or_404(user_id)
    if not user.lockout_until and user.failed_login_attempts == 0:
        flash(f"Account '{user.username}' is not locked.", "info")
        return redirect(url_for('admin'))
        
    user.reset_failed_attempts()
    db.session.commit()
    
    log_security_event('ADMIN_USER_UNLOCK', current_user.username, 'SUCCESS', f"User {user.username} unlocked and lockout cleared.")
    flash(f"Security lockouts and failed attempt logs cleared for user '{user.username}'.", "success")
    return redirect(url_for('admin'))

@app.route('/admin/toggle-role/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def toggle_role(user_id):
    """Admin endpoint to elevate user role or demote an admin."""
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("Security violation: You cannot demote yourself from administrative roles.", "danger")
        return redirect(url_for('admin'))
        
    user.role = 'admin' if user.role == 'user' else 'user'
    db.session.commit()
    
    log_security_event('ADMIN_USER_ROLE_CHANGE', current_user.username, 'SUCCESS', f"User {user.username} role changed to {user.role.upper()}.")
    flash(f"Role configuration of '{user.username}' updated to '{user.role}'.", "success")
    return redirect(url_for('admin'))

if __name__ == '__main__':
    # Build logs directory on run if missing
    if not os.path.exists('logs'):
        os.makedirs('logs')
    # Dynamic host & port configuration loaded from environment variables
    host = os.environ.get('HOST', '127.0.0.1')
    port = int(os.environ.get('PORT', 8989))
    app.run(host=host, port=port)
