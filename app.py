import os
import json
import bcrypt
import subprocess
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash

app = Flask(__name__)
app.secret_key = os.urandom(24)

LOG_FILE = "logs.txt"
USER_DB = "users.json"

def write_log(event, user="anonymous"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ip = request.remote_addr
    log_entry = f"{timestamp} | {ip} | {event} user={user}\n"
    with open(LOG_FILE, "a") as f:
        f.write(log_entry)

def load_users():
    with open(USER_DB, "r") as f:
        return json.load(f)

@app.route('/')
def index():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password').encode('utf-8')
        
        users = load_users()
        write_log("LOGIN_ATTEMPT", username)

        if username in users:
            hashed = users[username].encode('utf-8')
            if bcrypt.checkpw(password, hashed):
                session['user'] = username
                write_log("LOGIN_SUCCESS", username)
                return redirect(url_for('dashboard'))
        
        write_log("LOGIN_FAIL", username)
        flash("Invalid credentials infrastructure access denied.", "error")
        
    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    output = ""
    target = ""
    
    if request.method == 'POST':
        target = request.form.get('target')
        write_log(f"PING_REQUEST input={target}", session['user'])
        
        # Real-world vulnerability demonstration: Direct shell execution
        # As requested, no sanitization is applied.
        try:
            # -c 2 for Linux/Mac, -n 2 for Windows
            cmd = f"ping -c 2 {target}"
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True)
        except subprocess.CalledProcessError as e:
            output = e.output
        except Exception as e:
            output = str(e)

    return render_template('dashboard.html', user=session['user'], output=output, target=target)

@app.route('/logout')
def logout():
    user = session.get('user', 'unknown')
    write_log("LOGOUT", user)
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)