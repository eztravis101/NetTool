import os, json, bcrypt, subprocess, socket, time, re, sys
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash

app = Flask(__name__)
app.secret_key = os.urandom(24)

DB_PATH = "users_db.json"
LOG_FILE = "audit_logs.json"

if not os.path.exists(DB_PATH):
    with open(DB_PATH, 'w') as f: json.dump({}, f)

def load_db():
    with open(DB_PATH, 'r') as f: return json.load(f)

def save_db(data):
    with open(DB_PATH, 'w') as f: json.dump(data, f, indent=4)

def complex_logger(event_type, input_val="", cmd="", output="", status_code=200, latency=0, error=""):
    """Advanced Forensic Logger"""
    start_time = time.time()
    special_chars = re.findall(r'[^a-zA-Z0-9\s\.]', input_val)
    
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "src_ip": request.remote_addr,
        "user": session.get('user', 'anonymous'),
        "session_id": hash(session.get('user', 'none')),
        "endpoint": request.path,
        "method": request.method,
        "input_raw": input_val,
        "input_analysis": {
            "length": len(input_val),
            "special_chars": list(set(special_chars))
        },
        "user_agent": request.headers.get('User-Agent'),
        "http_status": status_code,
        "latency_ms": round(latency * 1000, 2),
        "command_executed": cmd,
        "exit_code": 0 if "ttl=" in output.lower() else 1,
        "process_info": {
            "pid": os.getpid(),
            "ppid": os.getppid()
        },
        "event_type": event_type,
        "error": str(error)
    }
    
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(log_entry) + "\n")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        db = load_db()

        if username in db:
            flash("Username taken.", "error")
        else:
            hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            db[username] = {"password": hashed, "history": []}
            save_db(db)
            complex_logger("AUTH_REGISTER", input_val=username)
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        start = time.time()
        username = request.form.get('username')
        password = request.form.get('password').encode('utf-8')
        db = load_db()
        
        success = False
        if username in db and bcrypt.checkpw(password, db[username]['password'].encode('utf-8')):
            session['user'] = username
            success = True
        
        complex_logger("AUTH_LOGIN", input_val=username, latency=time.time()-start, 
                       status_code=200 if success else 401)
        
        if success: return redirect(url_for('dashboard'))
        flash("Invalid credentials.", "error")
        
    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user' not in session: return redirect(url_for('login'))
    
    username = session['user']
    db = load_db()
    output, target, dns_info = "", "", ""
    
    if request.method == 'POST':
        start = time.time()
        target = request.form.get('target')
        
        # 1. DNS Resolution Logic
        try:
            # Check if it's an IP
            socket.inet_aton(target)
            # It's an IP, get Hostname
            try:
                host_info = socket.gethostbyaddr(target)
                dns_info = f"Resolved Hostname: {host_info[0]}"
            except: dns_info = "No Reverse DNS found."
        except socket.error:
            # It's a Hostname, get IP
            try:
                ip_info = socket.gethostbyname(target)
                dns_info = f"Resolved IP: {ip_info}"
            except: dns_info = "Resolution Failed."

        # 2. Command Execution
        cmd = f"ping -c 2 {target}"
        try:
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True)
            status = "Success"
        except Exception as e:
            output = str(e.output) if hasattr(e, 'output') else "Host unreachable."
            status = "Failed"

        complex_logger("TOOL_PING", input_val=target, cmd=cmd, output=output, latency=time.time()-start)

        # 3. Update History
        db[username]['history'].insert(0, {"target": target, "status": status, "time": datetime.now().strftime("%H:%M:%S")})
        db[username]['history'] = db[username]['history'][:10]
        save_db(db)

    return render_template('dashboard.html', user=username, output=output, 
                           target=target, history=db[username]['history'], dns_info=dns_info)

@app.route('/logout')
def logout():
    complex_logger("AUTH_LOGOUT")
    session.clear()
    return redirect(url_for('login'))

from flask import send_file

@app.route('/download_logs')
def download_logs():
    return send_file("logs.txt", as_attachment=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
