import os, json, bcrypt, subprocess
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash

app = Flask(__name__)
app.secret_key = os.urandom(24)

DB_PATH = "data/users_db.json"

# Ensure DB exists
if not os.path.exists('data'): os.makedirs('data')
if not os.path.exists(DB_PATH):
    with open(DB_PATH, 'w') as f: json.dump({}, f)

def load_db():
    with open(DB_PATH, 'r') as f: return json.load(f)

def save_db(data):
    with open(DB_PATH, 'w') as f: json.dump(data, f, indent=4)

def write_log(event, user="anonymous"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("logs.txt", "a") as f:
        f.write(f"{timestamp} | {request.remote_addr} | {event} user={user}\n")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        db = load_db()

        if username in db:
            flash("Username already exists.", "error")
        else:
            hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            db[username] = {
                "hash": hashed,
                "history": [],
                "joined": datetime.now().strftime("%Y-%m-%d")
            }
            save_db(db)
            write_log("USER_REGISTERED", username)
            flash("Account created! Please login.", "success")
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password').encode('utf-8')
        db = load_db()
        
        if username in db and bcrypt.checkpw(password, db[username]['hash'].encode('utf-8')):
            session['user'] = username
            write_log("LOGIN_SUCCESS", username)
            return redirect(url_for('dashboard'))
        
        flash("Invalid credentials.", "error")
    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user' not in session: return redirect(url_for('login'))
    
    username = session['user']
    db = load_db()
    user_data = db[username]
    output = ""
    
    if request.method == 'POST':
        target = request.form.get('target')
        
        # Run Command
        try:
            cmd = f"ping -c 2 {target}"
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True)
            status = "Success"
        except Exception:
            output = "Ping request failed or host unreachable."
            status = "Failed"

        # Update History
        history_entry = {
            "target": target,
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "status": status
        }
        user_data['history'].insert(0, history_entry) # Add to top
        user_data['history'] = user_data['history'][:10] # Keep last 10
        save_db(db)
        
    return render_template('dashboard.html', 
                           user=username, 
                           history=user_data['history'], 
                           output=output)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
