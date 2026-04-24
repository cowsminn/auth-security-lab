import sqlite3
import os
from flask import Flask, request, redirect, url_for, session, render_template_string, flash

app = Flask(__name__)
app.secret_key = 'a-very-insecure-secret-key' 

DATABASE = 'v1.db'

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    if os.path.exists(DATABASE):
        os.remove(DATABASE)
    with app.app_context():
        db = get_db()
        with app.open_resource('v1.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # 4.1 Weak Password Policy: No validation
        # 4.2 Insecure Password Storage: Plaintext
        db = get_db()
        try:
            db.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, password))
            db.commit()
            flash("Registration successful! Please log in.")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Email already registered.")
            return redirect(url_for('register'))

    return '''
        <h2>Register</h2>
        <form method="post">
            Email: <input type="email" name="email" required><br>
            Password: <input type="password" name="password" required><br>
            <input type="submit" value="Register">
        </form>
        <p>Already have an account? <a href="{{ url_for('login') }}">Login here</a>.</p>
    '''

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        db = get_db()
        
        # 4.4 User Enumeration
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        
        if user:
            # 4.2 Insecure Password Storage: Plaintext comparison
            if user['password'] == password:
                # 4.5 Insecure Session Management
                session['user_id'] = user['id']
                session['role'] = user['role']
                flash("Logged in successfully!")
                return redirect(url_for('dashboard'))
            else:
                flash("Incorrect password.")
                return redirect(url_for('login'))
        else:
            flash("User not found.")
            return redirect(url_for('login'))

    return render_template_string('''
        <h2>Login</h2>
        {% with messages = get_flashed_messages() %}
          {% if messages %}
            <ul class=flashes>
            {% for message in messages %}
              <li>{{ message }}</li>
            {% endfor %}
            </ul>
          {% endif %}
        {% endwith %}
        <form method="post">
            Email: <input type="email" name="email" required><br>
            Password: <input type="password" name="password" required><br>
            <input type="submit" value="Login">
        </form>
        <p>Don't have an account? <a href="{{ url_for('register') }}">Register here</a>.</p>
        <p><a href="{{ url_for('forgot_password') }}">Forgot your password?</a></p>
    ''')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    tickets = db.execute("SELECT * FROM tickets WHERE owner_id = ?", (session['user_id'],)).fetchall()

    return render_template_string('''
        <h2>Dashboard</h2>
        <p>Welcome! You are logged in as user #{{ session['user_id'] }} with role {{ session['role'] }}.</p>
        <h3>Your Tickets</h3>
        <ul>
            {% for ticket in tickets %}
                <li>{{ ticket['title'] }} - {{ ticket['status'] }}</li>
            {% else %}
                <li>No tickets found.</li>
            {% endfor %}
        </ul>
        <a href="{{ url_for('logout') }}">Logout</a>
    ''', tickets=tickets)

@app.route('/logout')
def logout():
    # 4.5 Does not properly invalidate session token, just clears from client
    session.pop('user_id', None)
    session.pop('role', None)
    flash("You have been logged out.")
    return redirect(url_for('login'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if user:
            # 4.6 Insecure Password Reset: Predictable token
            reset_token = f"reset_{user['id']}_{user['email']}"
            flash(f"Password reset link sent (for demo): /reset_password?token={reset_token}")
        else:
            flash("If a user with that email exists, a reset link has been sent.")
        return redirect(url_for('forgot_password'))

    return render_template_string('''
        <h2>Forgot Password</h2>
        {% with messages = get_flashed_messages() %}
          {% if messages %}
            <ul class=flashes>
            {% for message in messages %}
              <li>{{ message }}</li>
            {% endfor %}
            </ul>
          {% endif %}
        {% endwith %}
        <form method="post">
            Email: <input type="email" name="email" required><br>
            <input type="submit" value="Send Reset Link">
        </form>
    ''')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    token = request.args.get('token')
    if not token:
        return "Invalid token.", 400

    # 4.6 Insecure Password Reset: Reusable & predictable token
    try:
        parts = token.split('_')
        user_id = int(parts[1])
        email = parts[2]
    except (IndexError, ValueError):
        return "Invalid token format.", 400

    if request.method == 'POST':
        password = request.form['password']
        db = get_db()
        db.execute("UPDATE users SET password = ? WHERE id = ? AND email = ?", (password, user_id, email))
        db.commit()
        flash("Password has been reset successfully!")
        return redirect(url_for('login'))

    return render_template_string('''
        <h2>Reset Password</h2>
        <form method="post">
            New Password: <input type="password" name="password" required><br>
            <input type="submit" value="Reset Password">
        </form>
    ''')

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
