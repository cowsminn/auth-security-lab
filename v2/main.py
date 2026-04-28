import sqlite3
import os
import re
from datetime import datetime, timedelta
from flask import Flask, request, redirect, url_for, session, render_template_string, flash, g
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from functools import wraps

app = Flask(__name__)
app.secret_key = os.urandom(24)

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

DATABASE = 'v2.db'
MAX_FAILED_LOGINS = 3
LOCKOUT_TIME_MINUTES = 10
LOCKOUT_PERIOD = timedelta(minutes=15)

bcrypt = Bcrypt(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)
ts = URLSafeTimedSerializer(app.secret_key)

ip_blacklist = {}


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

@app.after_request
def add_security_headers(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

def init_db():
    if os.path.exists(DATABASE):
        os.remove(DATABASE)
    with app.app_context():
        db = get_db()
        with app.open_resource('v2.sql', mode='r') as f:
            db.cursor().executescript(f.read())
            
        users_to_add = [
        ('admin@test.com', bcrypt.generate_password_hash('AdminPass123!').decode('utf-8'), 'MANAGER'),
        ('cosmin@test.com', bcrypt.generate_password_hash('CosminPass123!').decode('utf-8'), 'ANALYST')
        ]
        db.executemany("INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)", users_to_add)
        
        db.commit()

def log_audit(user_id, action, resource=None, resource_id=None, ip_address=None):
    db = get_db()
    db.execute(
        "INSERT INTO audit_logs (user_id, action, resource, resource_id, ip_address) VALUES (?, ?, ?, ?, ?)",
        (user_id, action, resource, resource_id, ip_address)
    )
    db.commit()

def is_password_complex(password):
    if len(password) < 10:
        return False, "Password must be at least 10 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain an uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain a lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain a digit."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain a special character."
    return True, ""

def check_ip_blocked():
    client_ip = get_remote_address()
    if client_ip in ip_blacklist:
        lockout_until = ip_blacklist[client_ip]
        if datetime.utcnow() < lockout_until:
            return True
        else:
            ip_blacklist.pop(client_ip, None)
    return False

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute") 
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        is_complex, message = is_password_complex(password)
        if not is_complex:
            flash(message, 'error')
            return redirect(url_for('register'))

        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        
        db = get_db()
        try:
            db.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", (email, password_hash))
            db.commit()
            flash("Registration successful! Please log in.", 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("An error occurred.", 'error')
            return redirect(url_for('register'))

    return render_template_string('''
        <h2>Register</h2>
        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            {% for category, message in messages %}
              <div class="{{ category }}">{{ message }}</div>
            {% endfor %}
          {% endif %}
        {% endwith %}
        <form method="post">
            Email: <input type="email" name="email" required><br>
            Password: <input type="password" name="password" required><br>
            <input type="submit" value="Register">
        </form>
        <p>Already have an account? <a href="{{ url_for('login') }}">Login here</a>.</p>
    ''')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("20 per minute")
def login():
    if check_ip_blocked():
        flash("Your IP is temporarily blocked due to too many failed login attempts.", 'error')
    elif request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        db = get_db()
        
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        if user and user['lock_until'] and datetime.strptime(user['lock_until'], '%Y-%m-%d %H:%M:%S.%f') > datetime.utcnow():
            flash(f"Account is locked. Try again later.", 'error')
            return redirect(url_for('login'))

        if user and bcrypt.check_password_hash(user['password_hash'], password):
            db.execute("UPDATE users SET failed_login_attempts = 0, lock_until = NULL WHERE id = ?", (user['id'],))
            db.commit()

            session.clear()
            session['user_id'] = user['id']
            session['role'] = user['role']
            session.permanent = True
            app.permanent_session_lifetime = timedelta(minutes=30)

            log_audit(user['id'], 'LOGIN_SUCCESS', ip_address=request.remote_addr)
            flash("Logged in successfully!", 'success')
            return redirect(url_for('dashboard'))
        else:
            if user:
                attempts = user['failed_login_attempts'] + 1
                if attempts >= MAX_FAILED_LOGINS:
                    lock_time = datetime.utcnow() + timedelta(minutes=LOCKOUT_TIME_MINUTES)
                    db.execute("UPDATE users SET failed_login_attempts = ?, lock_until = ? WHERE id = ?", (attempts, lock_time, user['id']))
                    
                    client_ip = get_remote_address()
                    ip_blacklist[client_ip] = datetime.utcnow() + LOCKOUT_PERIOD
                    
                    log_audit(user['id'], 'ACCOUNT_LOCKED', ip_address=request.remote_addr)
                else:
                    db.execute("UPDATE users SET failed_login_attempts = ? WHERE id = ?", (attempts, user['id']))
                db.commit()
                log_audit(user['id'], 'LOGIN_FAILURE', ip_address=request.remote_addr)

            flash("Invalid email or password.", 'error')
            return redirect(url_for('login'))

    return render_template_string('''
        <h2>Login</h2>
        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            {% for category, message in messages %}
              <div class="{{ category }}">{{ message }}</div>
            {% endfor %}
          {% endif %}
        {% endwith %}
        <form method="post">
            Email: <input type="email" name="email" required><br>
            Password: <input type="password" name="password" required><br>
            <input type="submit" value="Login">
        </form>
        <p><a href="{{ url_for('forgot_password') }}">Forgot your password?</a></p>
        <p>Don't have an account? <a href="{{ url_for('register') }}">Register here</a>.</p>
    ''')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template_string('''
        <h2>Secure Dashboard</h2>
        <p>Welcome, user #{{ session['user_id'] }}!</p>
        <br>
        <a href="{{ url_for('logout') }}">Logout</a>
    ''')

@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    if user_id:
        log_audit(user_id, 'LOGOUT', ip_address=request.remote_addr)
    session.clear()
    flash("You have been logged out.", 'success')
    return redirect(url_for('login'))

@app.route('/forgot_password', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = get_db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        
        if user:
            token = ts.dumps(email, salt='password-reset-salt')
            reset_url = url_for('reset_password', token=token, _external=True)
            print(f"Reset URL (do not show in production): {reset_url}")

        flash("If an account with that email exists, a password reset link has been sent.", 'info')
        return redirect(url_for('forgot_password'))

    return render_template_string('''
        <h2>Forgot Password</h2>
        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            {% for category, message in messages %}
              <div class="{{ category }}">{{ message }}</div>
            {% endfor %}
          {% endif %}
        {% endwith %}
        <form method="post">
            Email: <input type="email" name="email" required><br>
            <input type="submit" value="Send Reset Link">
        </form>
    ''')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def reset_password(token):
    try:
        email = ts.loads(token, salt='password-reset-salt', max_age=1800)
    except SignatureExpired:
        flash("The password reset link has expired.", 'error')
        return redirect(url_for('login'))
    except BadTimeSignature:
        flash("Invalid password reset link.", 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form['password']
        is_complex, message = is_password_complex(password)
        if not is_complex:
            flash(message, 'error')
            return redirect(url_for('reset_password', token=token))

        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        db = get_db()
        db.execute("UPDATE users SET password_hash = ? WHERE email = ?", (password_hash, email))
        db.commit()
        
        user = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if user:
            log_audit(user['id'], 'PASSWORD_RESET_SUCCESS', ip_address=request.remote_addr)

        flash("Your password has been reset successfully!", 'success')
        return redirect(url_for('login'))

    return render_template_string('''
        <h2>Reset Password</h2>
        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            {% for category, message in messages %}
              <div class="{{ category }}">{{ message }}</div>
            {% endfor %}
          {% endif %}
        {% endwith %}
        <form method="post">
            New Password: <input type="password" name="password" required><br>
            <input type="submit" value="Reset Password">
        </form>
    ''')

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5001)
