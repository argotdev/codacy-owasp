from flask import Flask, request, jsonify, render_template_string, session
import sqlite3
import hashlib
import os
import pickle

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Used for session management

# Database setup
def init_db():
    conn = sqlite3.connect('vulnerable_app.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')
    c.execute('''INSERT OR IGNORE INTO users (username, password) VALUES ('admin', 'admin')''')
    conn.commit()
    conn.close()

# Injection Vulnerability
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('vulnerable_app.db')
        c = conn.cursor()
        # Vulnerable to SQL Injection
        c.execute(f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'")
        user = c.fetchone()
        conn.close()
        if user:
            session['username'] = username
            return 'Logged in as ' + username
        else:
            return 'Invalid credentials'
    return '''
        <form method="post">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Login">
        </form>
    '''

# Broken Authentication
@app.route('/admin')
def admin():
    if session.get('username') == 'admin':
        return 'Welcome to the admin page'
    else:
        return 'Access denied'

# Sensitive Data Exposure
@app.route('/hash_password', methods=['POST'])
def hash_password():
    password = request.form['password']
    # Weak hash algorithm (MD5)
    hashed_password = hashlib.md5(password.encode()).hexdigest()
    return jsonify({'hashed_password': hashed_password})

# XML External Entities (XXE)
@app.route('/parse_xml', methods=['POST'])
def parse_xml():
    xml_data = request.data
    try:
        # Vulnerable to XXE
        from lxml import etree
        doc = etree.fromstring(xml_data)
        return etree.tostring(doc)
    except Exception as e:
        return str(e)

# Broken Access Control
@app.route('/user/<int:user_id>')
def get_user(user_id):
    conn = sqlite3.connect('vulnerable_app.db')
    c = conn.cursor()
    # Direct object reference without proper authorization check
    c.execute("SELECT * FROM users WHERE id=?", (user_id,))
    user = c.fetchone()
    conn.close()
    if user:
        return jsonify({'id': user[0], 'username': user[1]})
    return 'User not found'

# Security Misconfiguration
@app.route('/debug')
def debug():
    # Exposing debug information
    return str(app.config)

# Cross-Site Scripting (XSS)
@app.route('/greet', methods=['GET', 'POST'])
def greet():
    if request.method == 'POST':
        name = request.form['name']
        # Vulnerable to XSS
        return render_template_string('<h1>Hello, {}!</h1>'.format(name))
    return '''
        <form method="post">
            Name: <input type="text" name="name"><br>
            <input type="submit" value="Greet">
        </form>
    '''

# Insecure Deserialization
@app.route('/load_object', methods=['POST'])
def load_object():
    serialized_object = request.data
    # Vulnerable to insecure deserialization
    obj = pickle.loads(serialized_object)
    return str(obj)

# Using Components with Known Vulnerabilities
@app.route('/vulnerable_component')
def vulnerable_component():
    # Using an old version of a library
    import urllib3
    http = urllib3.PoolManager()
    r = http.request('GET', 'http://httpbin.org/robots.txt')
    return r.data

# Insufficient Logging & Monitoring
@app.route('/transfer_money', methods=['POST'])
def transfer_money():
    sender = request.form['sender']
    recipient = request.form['recipient']
    amount = request.form['amount']
    # Insufficient logging
    return f'{amount} transferred from {sender} to {recipient}'

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
