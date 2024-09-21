from flask import send_file, abort
from datetime import datetime
from flask import render_template, redirect, url_for, session, make_response
from flask import Flask, request, url_for, jsonify, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import secrets
import sys
import yaml
import os
import requests
from pathlib import Path
from bark import bark_sender

app = Flask(__name__, template_folder='templates')
app.secret_key = secrets.token_hex(16)
domain_types = ['DOMAIN-SUFFIX', 'DOMAIN', 'DOMAIN-KEYWORD', 'GEOSITE', 'RULE-SET', 'IP-CIDR']
rule_types = ['Proxy', 'DIRECT', 'Mitm', 'Hijacking', 'SafeDNS']
login_manager = LoginManager(app)
login_manager.login_view = 'login'

with open(sys.argv[1], 'r', encoding='utf-8') as f:
    configuration = yaml.load(f.read(), Loader=yaml.FullLoader)
users = configuration['users_keys']
extra_rules_yaml = configuration['extra_rules_yaml']
update_sh = configuration['update_sh']
# rule_sets = [rs for rs in configuration['rule_providers']]
rule_sets = configuration['rule_providers']
update_subscription_sh = configuration['update_subscription_sh']
temp_yaml = configuration['temp_yaml']
rules = []
ruleset_rules = []

barker = bark_sender(configuration['bark']['server'], configuration['bark']['port'], configuration['bark']['https'],
                     configuration['bark']['key'], configuration['bark']['icon'])


# 创建 User 类，继承 UserMixin 用于管理登录状态
class User(UserMixin):
    def __init__(self, username):
        self.id = username


def query_ip_detail(ip):
    url = f'https://ipinfo.io/{ip}/json?token={configuration["ipinfo_token"]}'
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()  # Raise an exception for HTTP errors
        data = response.json()
        if data.get('bogon'):
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


def update_rule_set(rule_set: str) -> int:
    url = f'{configuration["clash"]["server"]}/providers/rules/{rule_set}'
    headers = {'Accept': '*/*', 'Accept-Encoding': 'gzip, deflate, br, zstd',
               'Authorization': f'Bearer {configuration["clash"]["secret"]}',
               'Content-Length': '0', 'Content-Type': 'application/json', 'Priority': 'u=1, i'}
    r = requests.put(url, headers=headers, timeout=5)
    return r.status_code


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
                    'Config version': 'normal' if not version else version,
					'URL': f'{request.base_url}'}
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


@app.route('/rule_providers')
def server_rule_providers():
    if request.args.get('permission') not in users:
        abort(404)
    rule_set = request.args.get('rule_set')
    if not rule_set:
        abort(404)
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    headers = {'Time': f'{current_time}',
               'Content-Type': 'application/octet-stream; charset=utf-8',
               'Content-Disposition': f'attachment; filename="{rule_set}.yaml"'}
    # user_agent = request.headers.get('User-Agent')
    try:
        with open(temp_yaml, 'r', encoding='utf-8') as fl:
            temp = yaml.load(fl.read(), Loader=yaml.FullLoader)
            headers['Subscription-Userinfo'] = \
                f'upload={temp["upload"]}; download={temp["download"]}; total={temp["total"]}; expire={temp["expire"]}'
    except Exception as e:
        print(f"Fail to open {temp_yaml}: {e}")
    response = make_response(send_file(configuration['rule_providers'][rule_set]['path'], as_attachment=True))
    response.headers = headers
    return response


@app.route('/')
@login_required
def home():
    return redirect(url_for('ptproxy'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username]['password'] == password:
            user = User(username)
            login_user(user)
            flash("Logged in successfully!", "success")
            return redirect(url_for('ptproxy'))
        else:
            flash("Invalid credentials", "danger")
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    # session.pop('username', None)
    logout_user()
    flash("Logged out successfully!", "info")
    return redirect(url_for('login'))


# API 返回所有规则 (用于实时获取)，受保护路由
@app.route('/api/rules')
@login_required
def get_rules():
    # 获取分页参数
    page = int(request.args.get('page', 1))  # 默认页码为1
    limit = int(request.args.get('limit', 10))  # 每页默认10条记录

    # 计算分页的起始和结束位置
    start = (page - 1) * limit
    end = start + limit

    # 获取当前分页的规则
    paginated_rules = rules[start:end]

    # 返回数据总条数和分页后的规则
    return jsonify({
        'total': len(rules),
        'page': page,
        'limit': limit,
        'rules': paginated_rules
    })


@app.route('/api/ruleset/rules')
@login_required
def get_ruleset_rules():
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 10))

    # 计算分页的起始和结束位置
    start = (page - 1) * limit
    end = start + limit

    # 获取当前分页的规则
    paginated_rules = ruleset_rules[start:end]

    # 返回数据总条数和分页后的规则
    return jsonify({
        'total': len(ruleset_rules),
        'page': page,
        'limit': limit,
        'rules': paginated_rules
    })


@app.route('/ptproxy', methods=['GET'])
@login_required
def ptproxy():
    return render_template('ptproxy.html')


@app.route('/ruleset', methods=['GET'])
@login_required
def ruleset():
    return render_template('ruleset.html')


# 增加规则
@app.route('/add', methods=['POST'])
@login_required
def add_rule():
    if request.method == 'POST':
        rule_type = request.form['type']
        value = request.form['value']
        policy = request.form['policy']
        option = request.form['option']
        rule_id = max([rule["id"] for rule in rules]) + 1 if rules else 1
        new_rule = {"id": rule_id, "type": rule_type, "value": value,
                    "policy": policy, "option": None if option == 'None' else 'no-resolve'}
        rules.append(new_rule)
        return redirect(url_for('ptproxy'))


@app.route('/ruleset/add', methods=['POST'])
@login_required
def add_ruleset_rule():
    if request.method == 'POST':
        wildcard_type = request.form['wildcard_type']
        value = request.form['value']
        rule_set = request.form['rule_set']
        rule_id = max([rule["id"] for rule in ruleset_rules]) + 1 if ruleset_rules else 1
        new_rule = {"id": rule_id, "wildcard_type": wildcard_type, "value": value,
                    "rule_set": rule_set}
        ruleset_rules.append(new_rule)
        save_ruleset_rules(rule_sets)
        return redirect(url_for('ruleset'))


@app.route('/delete/<int:rule_id>')
@login_required
def delete_rule(rule_id):
    global rules
    rules = [rule for rule in rules if rule["id"] != rule_id]
    return redirect(url_for('ptproxy'))


@app.route('/ruleset/delete/<int:rule_id>')
@login_required
def delete_ruleset_rule(rule_id):
    global ruleset_rules
    ruleset_rules = [rule for rule in ruleset_rules if rule["id"] != rule_id]
    save_ruleset_rules(rule_sets)
    return redirect(url_for('ruleset'))


@app.route('/edit/<int:rule_id>')
@login_required
def edit_rule(rule_id):
    rule = next((rule for rule in rules if rule["id"] == rule_id), None)
    return render_template('edit.html', rule=rule)


@app.route('/update/<int:rule_id>', methods=['POST'])
@login_required
def update_rule(rule_id):
    if request.method == 'POST':
        rule_type = request.form['type']
        value = request.form['value']
        policy = request.form['policy']
        option = request.form['option']

        for rule in rules:
            if rule['id'] == rule_id:
                rule['type'] = rule_type
                rule['value'] = value
                rule['policy'] = policy
                rule['option'] = None if option == 'None' else 'no-resolve'
                break
        return redirect(url_for('ptproxy'))


@app.route('/save-rules-to-file', methods=['POST'])
@login_required
def save_rules_to_file():
    save_rules(extra_rules_yaml)
    return jsonify({"message": "Rules saved successfully"}), 200


@app.route('/update-config-file', methods=['POST'])
@login_required
def update_config_file():
    if not os.system(update_sh):
        return jsonify({"message": "Config updated successfully"}), 200
    else:
        return jsonify({"message": "Fail to update clash config"}), 500


@app.route('/process_rule', methods=['POST'])
def process_rule():
    if 'username' not in session:
        return redirect(url_for('login'))
    domain = request.form['domainInput']
    wildcard_type = request.form['wildcard_type']
    rule_set = request.form.get('rule_set')
    if rule_set not in rule_sets:
        alert_message = f'Unknown rule set: {rule_set}'
        return render_template('ptproxy.html', alert_message=alert_message)
    with open(configuration['rule_providers'][rule_set]['path'], 'r', encoding='utf-8') as f:
        file_data = f.read()
        proxied_rules = yaml.load(file_data, Loader=yaml.FullLoader)
    rule = f'{wildcard_type}{domain}'
    proxied_rules['payload'].append(rule)
    proxied_rules_string = yaml.dump(proxied_rules, allow_unicode=True)
    with open(configuration['rule_providers'][rule_set]['path'], 'w+') as file:
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
    update_rule_set(rule_set)
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
@login_required
def apply_changes():
    # Check if the user is logged in
    if os.system(update_sh):
        return "Fail to Update Clash Config"
    os.system(update_subscription_sh)
    return "Changes Applied Successfully!"


# 设置加载用户回调函数
@login_manager.user_loader
def load_user(user_id):
    if user_id in users:
        return User(user_id)
    return None


def load_rules(rules_path: str) -> list:
    global rules
    with open(rules_path, 'r', encoding='utf-8') as f:
        file_data = f.read()
        extra_rules = yaml.load(file_data, Loader=yaml.FullLoader)
        rules = []
        line_number = 0
        for rule_string in extra_rules['rules']:
            r = rule_string.split(',')
            if r[0] == 'MATCH':
                rule = {"id": line_number, "type": r[0], "value": r[1], "policy": None, 'option': None}
            elif len(r) == 3:
                rule = {"id": line_number, "type": r[0], "value": r[1], "policy": r[2], 'option': None}
            else:
                rule = {"id": line_number, "type": r[0], "value": r[1], "policy": r[2], 'option': r[3]}
            rules.append(rule)
            line_number += 1
    return rules


def load_ruleset_rules(sets) -> list:
    global ruleset_rules
    ruleset_rules = []
    line_number = 0
    for rule_set in sets:
        with open(sets[rule_set]['path'], 'r', encoding='utf-8') as f:
            file_data = f.read()
            rs = yaml.load(file_data, Loader=yaml.FullLoader)
            for rule_string in rs['payload']:
                rule = {"id": line_number, 'wildcard_type': '', 'rule_set': rule_set, 'value': rule_string}
                ruleset_rules.append(rule)
                line_number += 1
    return ruleset_rules


def save_rules(rules_path: str) -> list:
    extra_rules = {"rules": []}
    for rule in rules:
        rule_string = f'{rule["type"]},{rule["value"]},{rule["policy"]}'
        if rule['option']:
            rule_string += f',{rule["option"]}'
        extra_rules['rules'].append(rule_string)
    with open(rules_path, 'w+', encoding='utf-8') as f:
        extra_rules_string = yaml.dump(extra_rules, allow_unicode=True)
        f.write(extra_rules_string)
    return rules


def save_ruleset_rules(rulesets: dict) -> list:
    sets = {rs: [] for rs in rulesets}
    for rule in ruleset_rules:
        rule_string = f'{rule["wildcard_type"]}{rule["value"]}'
        sets[rule['rule_set']].append(rule_string)
    for rs in rule_sets:
        with open(rule_sets[rs]['path'], 'w+', encoding='utf-8') as f:
            string = yaml.dump({'payload': sets[rs]}, allow_unicode=True)
            f.write(string)
    return rules


if __name__ == '__main__':
    file_path = Path(temp_yaml)
    if not file_path.exists():
        file_path.touch()
        print(f"File '{temp_yaml}' created successfully.")
    load_rules(extra_rules_yaml)
    load_ruleset_rules(rule_sets)
    app.run(host='::', port=7887, debug=True)
