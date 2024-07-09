from flask import Flask, send_file, request, abort
from datetime import datetime
from flask import render_template, redirect, url_for, session, make_response
import secrets
import sys
import yaml
import os
import requests
import json
from pathlib import Path

app = Flask(__name__, template_folder='templates')
app.secret_key = secrets.token_hex(16)
domain_types = ['DOMAIN-SUFFIX', 'DOMAIN', 'DOMAIN-KEYWORD']
rule_types = ['Proxy', 'DIRECT', 'Mitm', 'Hijacking', 'SafeDNS']

with open(sys.argv[1], 'r', encoding='utf-8') as f:
    file_data = f.read()
    configuration = yaml.load(file_data, Loader=yaml.FullLoader)
users = configuration['users_keys']
extra_rules_yaml = configuration['extra_rules_yaml']
update_sh = configuration['update_sh']
update_subscription_sh = configuration['update_subscription_sh']
temp_yaml = configuration['temp_yaml']
file_path = Path(temp_yaml)

if not file_path.exists():
    file_path.touch()
    print(f"File '{temp_yaml}' created successfully.")


def bark_notify(title, content):
    url = f"{configuration['bark']['server']}/{configuration['bark']['key']}"
    data = {"body": content,
            "title": title,
            # "device_key": configuration['bark']['key'],
            "icon": configuration['bark']['icon'],
            "sound": "glass.caf"}
    params = {'icon': 'https://raw.githubusercontent.com/walkxcode/dashboard-icons/main/png/cloudflare-pages.png',
              "group": configuration['bark']['group']}
    json_data = json.dumps(data)
    headers = {"Content-Type": "application/json; charset=utf-8"}
    try:
        response = requests.post(url, data=json_data, headers=headers, params=params, timeout=1)
    except Exception as e:
        print(f"Fail to send bark notification {e}")
        return 0
    return response.status_code


def check_exist_rule(rule, extra_rules):
    for r in extra_rules:
        if r == rule:
            return True
    return False


@app.route('/config')
def server_config():
    if request.args.get('permission') not in users:
        abort(404)
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    headers = {'Time': f'{current_time}',
               'Content-Type': 'application/octet-stream; charset=utf-8',
               'Content-Disposition': 'attachment; filename="ptproxy.yaml"'}
    user_agent = request.headers.get('User-Agent')
    try:
        with open(temp_yaml, 'r', encoding='utf-8') as fl:
            temp = yaml.load(fl.read(), Loader=yaml.FullLoader)
            headers['Subscription-Userinfo'] = \
                f'upload={temp["upload"]}; download={temp["download"]}; total={temp["total"]}; expire={temp["expire"]}'
    except Exception as e:
        print(f"Fail to open {temp_yaml}: {e}")
    response = make_response(send_file(configuration['out_without_mitm_yaml'], as_attachment=True))
    response.headers = headers
    real_ip = request.headers['X-Real-IP']
    bark_notify(f'【PtProxy】 {request.args.get("permission")} is updating config', f'{current_time}\n\nIP address: \t{real_ip}\nUser-Agent: \t{user_agent}')
    return response


@app.route('/bypassed_list')
def server_bypassed_list():
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    headers = {'Time': f'{current_time}',
               'Content-Type': 'application/octet-stream; charset=utf-8',
               'Content-Disposition': 'attachment; filename="bypassed_list.txt"'}
    user_agent = request.headers.get('User-Agent')
    response = make_response(send_file('bypassed_list.txt', as_attachment=True))
    response.headers = headers
    real_ip = request.headers['X-Real-IP']
    bark_notify(f'【PtProxy】 Request to update bypassed list', f'{current_time}\n\nIP address: \t{real_ip}\nUser-Agent: \t{user_agent}')
    return response

@app.route('/proxied_rules')
def server_proxied_rules():
    if request.args.get('permission') not in users:
        abort(404)
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    headers = {'Time': f'{current_time}',
               'Content-Type': 'application/octet-stream; charset=utf-8',
               'Content-Disposition': 'attachment; filename="proxied_rules.yaml"'}
    user_agent = request.headers.get('User-Agent')
    print(user_agent)
    try:
        with open(temp_yaml, 'r', encoding='utf-8') as fl:
            temp = yaml.load(fl.read(), Loader=yaml.FullLoader)
            headers['Subscription-Userinfo'] = \
                f'upload={temp["upload"]}; download={temp["download"]}; total={temp["total"]}; expire={temp["expire"]}'
    except Exception as e:
        print(f"Fail to open {temp_yaml}: {e}")
    response = make_response(send_file(configuration['rule_providers']['proxied_rules_yaml'], as_attachment=True))
    response.headers = headers
    return response


@app.route('/direct_rules')
def server_direct_rules():
    if request.args.get('permission') not in users:
        abort(404)
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    headers = {'Time': f'{current_time}',
               'Content-Type': 'application/octet-stream; charset=utf-8',
               'Content-Disposition': 'attachment; filename="direct_rules.yaml"'}
    try:
        with open(temp_yaml, 'r', encoding='utf-8') as fl:
            temp = yaml.load(fl.read(), Loader=yaml.FullLoader)
            headers['Subscription-Userinfo'] = \
                f'upload={temp["upload"]}; download={temp["download"]}; total={temp["total"]}; expire={temp["expire"]}'
    except Exception as e:
        print(f"Fail to open {temp_yaml}: {e}")
    response = make_response(send_file(configuration['rule_providers']['direct_rules_yaml'], as_attachment=True))
    response.headers = headers
    return response


@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('ptproxy'))
    return redirect(url_for('login'))


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
    return redirect(url_for('login'))


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
    rule = f'{domain_type},{domain},{rule_type}'
    if check_exist_rule(rule, extra_rules):
        alert_message = f'[{rule}] has existed!'
        return render_template('ptproxy.html', alert_message=alert_message)
    extra_rules['rules'].append(rule)
    extra_rules_string = yaml.dump(extra_rules, allow_unicode=True)
    with open(extra_rules_yaml, 'w+') as file:
        file.write(extra_rules_string)
    alert_message = f'{domain} submitted successfully!'
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    bark_notify(f'【PtProxy】', f'{current_time}\n\n{session["username"]} Added a New Rule\n'
                              f'RULE \t{domain_type},{domain},{rule_type}\n'
                              f'IP \t{request.remote_addr}')
    return render_template('ptproxy.html', alert_message=alert_message)


@app.route('/apply_changes')
def apply_changes():
    # Check if the user is logged in
    if 'username' in session:
        if os.system(update_sh):
            return "Fail to Update Clash Config"
        os.system(update_subscription_sh)
        return "Changes Applied Successfully!"
    else:
        return redirect(url_for('login'))


@app.route('/check_login_status')
def check_login_status():
    # Check and return user login status
    if 'username' in session:
        return "OK"
    else:
        return "Unauthorized", 401


if __name__ == '__main__':
    app.run(host='::', port=7887)
