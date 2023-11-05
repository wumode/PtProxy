from flask import Flask, send_file, request, abort
from datetime import datetime
from flask import render_template, redirect, url_for, session, jsonify
import secrets
import sys
import yaml

app = Flask(__name__, template_folder='templates')
app.secret_key = secrets.token_hex(16)
# Mock user database (replace this with a proper user authentication system)
domain_types = ['DOMAIN-SUFFIX', 'DOMAIN', 'DOMAIN-KEYWORD']
rule_types = ['Proxy', 'DIRECT', 'Mitm', 'Hijacking']

with open(sys.argv[1], 'r', encoding='utf-8') as f:
    file_data = f.read()
    configuration = yaml.load(file_data, Loader=yaml.FullLoader)
users = configuration['users_keys']
extra_rules_yaml = configuration['extra_rules_yaml']


@app.route('/config.yaml')
def serve_config():
    # Check for permission (you can customize this logic)
    if request.args.get('permission') != 'granted':
        abort(404)

    # Customize the response headers based on current time
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    headers = {'Custom-Header': f'{current_time}',
               'Subscription-Userinfo': 'upload=831029914; download=39919943627; total=161112653824; expire=1700708875'}

    # Serve the specific file (config.yaml in this example)
    return send_file('config.yaml', as_attachment=True, headers=headers)


@app.route('/')
def home():
    if 'username' in session:
        return f'Logged in as {session["username"]}<br><a href="/logout">Logout</a>'
    return 'You are not logged in<br><a href="/login">Login</a>'


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username] == password:
            session['username'] = username
            return redirect(url_for('ptproxy_page'))
        return 'Invalid username or password'
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))


@app.route('/ptproxy', methods=['GET'])
def ptproxy_page():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('ptproxy.html')


@app.route('/process_domain', methods=['POST'])
def process_domain():
    if 'username' not in session:
        return redirect(url_for('login'))
    domain = request.form['domain']
    domain_type = request.form['domain_type']
    rule_type = request.form['rule_type']
    if domain_type not in domain_types or rule_type not in rule_types:
        alert_message = f'unknown rule or domain type'
        return render_template('ptproxy.html', alert_message=alert_message)
    with open(extra_rules_yaml, 'r', encoding='utf-8') as f:
        file_data = f.read()
        extra_rules = yaml.load(file_data, Loader=yaml.FullLoader)
    extra_rules['rules'].append(f'{domain_type},{domain},{rule_type}')
    extra_rules_string = yaml.dump(extra_rules, allow_unicode=True)
    with open(extra_rules_yaml, 'w+') as file:
        file.write(extra_rules_string)
    alert_message = f'{domain} submitted successfully!'
    return render_template('ptproxy.html', alert_message=alert_message)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=7887)
