# Cyber-Sentinel: Production-Ready Secure Login System

An enterprise-grade, high-fidelity **Secure Login and Registration System** built using Python Flask. This application demonstrates cybersecurity best practices, robust defensive programming, and modern UI design. Perfect for a cybersecurity resume, portfolio, or GitHub project.

---

## 🛠️ Security Architecture & Features

This system is built from the ground up prioritizing security. Below is a detailed breakdown of the active defense layers:

### 1. Cryptographically Secure Password Storage
* **Algorithm**: **BCrypt** (via Python `bcrypt` library).
* **Implementation**: Uses a salted, slow hashing design with a work factor of 12 rounds. This is computationally expensive, drastically mitigating dictionary and precomputed table (rainbow table) brute force attacks.
* **Hardenings**: Plaintext passwords are never logged, held in local memory longer than necessary, or written to physical disks.

### 2. Multi-Factor Authentication (2FA / MFA)
* **Algorithm**: Time-based One-Time Password (TOTP) conforming to **RFC 6238** (via `pyotp`).
* **Provisioning**: Generates a secure random 32-character base32 secret. Renders a standard QR URI scanned directly into Google Authenticator, Microsoft Authenticator, or Bitwarden.
* **Transmission**: QR codes are rendered strictly in-memory as inline Base64 images to prevent sensitive filesystem storage leakages.
* **Drift Window**: Configured with a `valid_window=1` (30-second clock skew tolerance before/after) to keep validation robust yet secure against replays.

### 3. Defensive Session & Cookie Hardening
* **HttpOnly**: Set to `True`. Prevents client-side scripts from reading session cookies, shielding the application from token hijacking via Cross-Site Scripting (XSS) attacks.
* **Secure**: Set to `True` (enforced automatically in production). Ensures cookies are only transmitted over TLS/HTTPS encrypted connections.
* **SameSite**: Enforced as `Lax`. Mitigates Cross-Site Request Forgery (CSRF) vectors by ensuring cookies are not sent with cross-site requests.
* **Inactivity Session Timeout**: Automatically terminates system sessions after **15 minutes** of continuous user inactivity, with log auditing.

### 4. Brute-Force Throttling & Account Lockout
* **IP Throttling**: Implemented **Flask-Limiter** using Redis/In-memory buckets. Login and registration pathways are strictly throttled to a maximum of 5 attempts per minute per IP address (Code 429).
* **Account Lockout**: Tracks consecutive failed login attempts in the database. On the **5th failure**, the account is locked for **10 minutes** (`lockout_until` timestamp).
* **Anti-Username Enumeration**: Login validation returns generic "Invalid username/email or password" messages for both non-existent users and incorrect passwords to prevent credential harvesting.

### 5. Input Sanitization & SQLi/XSS Shields
* **SQL Injection (SQLi)**: Defeated by using **SQLAlchemy ORM** which automatically enforces parameterized query binds.
* **Cross-Site Scripting (XSS)**: Form fields are fully sanitized using **Flask-WTF** input constraints. The **Jinja2** rendering engine is configured with auto-escaping enabled for all template elements.

### 6. HTTP Secure Response Headers
Every outgoing HTTP response is injected with strict security headers via a custom Flask middleware:
* `Content-Security-Policy` (CSP): Strictly controls script, image, and style sources.
* `X-Frame-Options: DENY`: Prevents Clickjacking attacks.
* `X-Content-Type-Options: nosniff`: Prevents MIME type sniffing.
* `Referrer-Policy: strict-origin-when-cross-origin`: Restricts referral data leakage.
* `Permissions-Policy`: Hard-blocks browser access to device cameras, microphones, and GPS coordinates.

### 7. Logging & Anomaly Audits
* Configured rotating file logger (`logs/auth.log`) with automatic 5MB splits and 5-tier rotation.
* Tracks: Successful log-ins, failed attempts, account lockouts, 2FA toggles, and session timeouts.
* Captures client remote IP (supporting proxy headers) and user-agents, without ever recording sensitive parameters like passwords.

---

## 📂 Project Directory Structure

```text
Secure Login System/
├── .env                  # Runtime secrets (Git ignored)
├── .env.example          # Template configuration
├── .gitignore            # Version control filters
├── app.py                # Core Flask app, routing, and middleware
├── config.py             # Environment parser & security configurations
├── init_db.py            # SQLite schema compiler & database seeder
├── models.py             # SQLAlchemy models (User & LoginHistory)
├── forms.py              # WTForms validators & security rules
├── utils.py              # Security audit loggers, QR encoders, & decorators
├── requirements.txt      # Pinned dependency manifests
├── README.md             # Systems documentation
├── database/
│   └── secure_login.db  # Active SQLite database file (Git ignored)
├── logs/
│   └── auth.log         # Security audit trails file (Git ignored)
├── screenshots/          # Visual assets directory
├── static/
│   ├── css/
│   │   └── style.css     # Cyber-Sentinel custom theme CSS
│   └── js/
│       └── main.js       # Auto-dismiss alerts & real-time strength helper
└── templates/
    ├── base.html         # Master grid frame & custom error layouts
    ├── login.html        # Glassmorphic user login card
    ├── login_2fa.html    # Secondary authentication entry
    ├── register.html     # Setup registration with complexity indicators
    ├── dashboard.html    # Personal logs dashboard & active 2FA toggler
    ├── profile.html      # Security profile & password updates
    └── admin.html        # SecOps global console & user state manager
```

---

## 🚀 Setup & Installation Instructions

This guide is optimized for Windows systems:

### Prerequisite
Ensure Python is installed on your system. You can verify it and install the standard launcher by searching for Python in your Microsoft Store or downloading the installer from Python.org (ensure you check **"Add Python to PATH"** during installation).

### Step 1: Clone or Copy Project Files
Place the project directory in your chosen workspace folder:
```powershell
cd "C:\Users\DELL\OneDrive\g\Secure Login System"
```

### Step 2: Establish Virtual Environment (Recommended)
Creating an isolated environment prevents library version conflicts:
```powershell
# Create virtual environment
py -m venv venv

# Activate virtual environment
.\venv\Scripts\Activate.ps1
```

### Step 3: Install Required Dependencies
Install the pinned libraries:
```powershell
pip install -r requirements.txt
```

### Step 4: Configure Local Environment Settings
Create your active `.env` file from the provided example template:
```powershell
Copy-Item .env.example .env
```
*Note: In your active `.env` file, make sure to replace the placeholder secret keys with your own custom 64-character random hex strings.*

### Step 5: Initialize the Database
Run the pre-compiled database schema generator and account seeder:
```powershell
python init_db.py
```
This script will construct the SQLite tables and seed two standard development accounts:
1. **System Administrator**:
   * **Username**: `admin`
   * **Password**: `AdminSecure2026!`
2. **Standard Operative**:
   * **Username**: `user1`
   * **Password**: `UserSecure2026!`

### Step 6: Boot Up the Application
Launch the Flask development server:
```powershell
python app.py
```
Open your browser and navigate to the local gateway: **`http://127.0.0.1:5000`**

---

## 📈 Future Security Roadmap

Planned enterprise integrations:
1. **Email Verifications**: Integrate SendGrid/SMTP to enforce activation codes before account validation.
2. **Password Resets**: Safe tokenized password recovery pathways with temporary signed URL links.
3. **Role-Based Access Control (RBAC)**: Expand administrative granularity to separate standard operators, security analysts, and master administrators.
4. **OAuth 2.0 Integration**: Enable secure federated logins (Sign in with Google/GitHub) using OpenID Connect.
5. **Docker Containerization**: Build hardened, minimal distroless Docker images ready for production Kubernetes deployment.
