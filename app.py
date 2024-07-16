from flask import Flask, send_file, request, abort
from datetime import datetime
from flask import render_template, redirect, url_for, session, make_response
import secrets
import sys
import yaml
import os
import requests
from pathlib import Path
from bark import bark_sender

app = Flask(__name__, template_folder='templates')
app.secret_key = secrets.token_hex(16)
domain_types = ['DOMAIN-SUFFIX', 'DOMAIN', 'DOMAIN-KEYWORD']
rule_types = ['Proxy', 'DIRECT', 'Mitm', 'Hijacking', 'SafeDNS']

with open(sys.argv[1], 'r', encoding='utf-8') as f:
    configuration = yaml.load(f.read(), Loader=yaml.FullLoader)
users = configuration['users_keys']
extra_rules_yaml = configuration['extra_rules_yaml']
proxied_rules_yaml = configuration['rule_providers']['proxied_rules_yaml']
update_sh = configuration['update_sh']
update_subscription_sh = configuration['update_subscription_sh']
temp_yaml = configuration['temp_yaml']
file_path = Path(temp_yaml)
barker = bark_sender(configuration['bark']['server'], configuration['bark']['port'], configuration['bark']['https'],
                     configuration['bark']['key'], configuration['bark']['icon'])


if not file_path.exists():
    file_path.touch()
    print(f"File '{temp_yaml}' created successfully.")


def query_ip_detail(ip):
    url = f'https://ipinfo.io/{ip}/json?token={configuration["ipinfo_token"]}'
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()  # Raise an exception for HTTP errors
        data = response.json()
        if data['bogon']:
            return None
    except Exception as e:
        print(f"Fail to query ip {ip}")
        return None
    return data


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
    version = request.args.get('version')
    try:
        with open(temp_yaml, 'r', encoding='utf-8') as fl:
            temp = yaml.load(fl.read(), Loader=yaml.FullLoader)
            headers['Subscription-Userinfo'] = \
                f'upload={temp["upload"]}; download={temp["download"]}; total={temp["total"]}; expire={temp["expire"]}'
    except Exception as e:
        print(f"Fail to open {temp_yaml}: {e}")
    response_file = configuration['out_without_mitm_yaml']
    if version == 'mitm':
        response_file = configuration['out_yaml']
    elif version == 'local':
        response_file = configuration['out_local_yaml']
    response = make_response(send_file(response_file, as_attachment=True))
    response.headers = headers
    real_ip = request.remote_addr if not request.headers.get('X-Real-IP') else request.headers.get('X-Real-IP')
    ip_details = query_ip_detail(real_ip)
    location = f'{ip_details["country"]} {ip_details["region"]} {ip_details["city"]}' if ip_details else 'Unknown'
    message_data = {'IP address': f'{real_ip} ({location})',
                    'User agent': user_agent,
                    'Config version': 'normal' if not version else version}
    barker.bark_notify(f'{request.args.get("permission")} is updating config',
                       'Request details',
                       message_data,
                       configuration['bark']['group'],
                       'https://raw.githubusercontent.com/walkxcode/dashboard-icons/main/png/cloudflare-pages.png')
    return response


@app.route('/bypassed_list')
def server_bypassed_list():
    v = request.args.get('v')
    if not v or (v != '4' and v != '6'):
        abort(404)
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    headers = {'Time': f'{current_time}',
               'Content-Type': 'application/octet-stream; charset=utf-8',
               'Content-Disposition': 'attachment; filename="bypassed_list.txt"'}
    user_agent = request.headers.get('User-Agent')
    list_path = 'bypassed_list.txt' if v == '4' else 'ipv6_bypassed_list.txt'
    response = make_response(send_file(list_path, as_attachment=True))
    response.headers = headers
    real_ip = request.remote_addr if not request.headers.get('X-Real-IP') else request.headers.get('X-Real-IP')
    message_data = {'IP address': f'{real_ip}', 'User-Agent': user_agent, 'Version': f'IPv{v}'}
    barker.bark_notify(f'Request to update bypassed list',
                       'Request details',
                       message_data,
                       configuration['bark']['group'],
                       'https://raw.githubusercontent.com/walkxcode/dashboard-icons/main/png/cloudflare-pages.png')
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


@app.route('/process_rule', methods=['POST'])
def process_rule():
    if 'username' not in session:
        return redirect(url_for('login'))
    domain = request.form['domainInput']
    wildcard_type = request.form['wildcard_type']
    with open(proxied_rules_yaml, 'r', encoding='utf-8') as f:
        file_data = f.read()
        proxied_rules = yaml.load(file_data, Loader=yaml.FullLoader)
    rule = f'{wildcard_type}{domain}'
    proxied_rules['payload'].append(rule)
    proxied_rules_string = yaml.dump(proxied_rules, allow_unicode=True)
    with open(proxied_rules_yaml, 'w+') as file:
        file.write(proxied_rules_string)
    alert_message = f'`{rule}` submitted successfully!'
    user_agent = request.headers.get('User-Agent')
    message_data = {'RULE': f'{rule}', 'User-Agent': user_agent,
                    'IP': f'{request.headers["X-Real-IP"]}'}
    barker.bark_notify(f'Request to update proxied rules',
                       'Request details',
                       message_data,
                       configuration['bark']['group'],
                       'https://raw.githubusercontent.com/walkxcode/dashboard-icons/main/png/cloudflare-pages.png')
    return render_template('ptproxy.html', alert_message=alert_message)


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
    alert_message = f'`{domain}` submitted successfully!'
    user_agent = request.headers.get('User-Agent')
    message_data = {'RULE': f'{domain_type},{domain},{rule_type}', 'User-Agent': user_agent,
                    'IP': f'{request.headers["X-Real-IP"]}'}
    barker.bark_notify(f'Request to update rules',
                       'Request details',
                       message_data,
                       configuration['bark']['group'],
                       'https://raw.githubusercontent.com/walkxcode/dashboard-icons/main/png/cloudflare-pages.png')
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
