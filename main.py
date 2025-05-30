# -*- coding:utf-8 -*-
# -*- author:wumo -*-

import base64
import requests
import socket
import json
import yaml
import socket
import random
import urllib
import re
import os
from ping3 import ping
import sys
from urllib.parse import urlparse, parse_qs
from typing import Optional

from bark import bark_sender


def read_yaml(path) -> Optional[dict]:
    with open(path, 'r', encoding='utf-8') as f:
        file_data = f.read()
        rs = yaml.load(file_data, Loader=yaml.FullLoader)
        return rs


if len(sys.argv) < 2:
    print('No configuration file')
    exit(-1)
configuration = read_yaml(sys.argv[1])

barker = bark_sender(configuration['bark']['server'], configuration['bark']['port'], configuration['bark']['https'],
                     configuration['bark']['key'], configuration['bark']['icon'])

filter_keywords = configuration['filter_keywords']
sub_link_list = configuration['subscribe_links']
out_yaml = configuration['out_yaml']

log_path = configuration['log_path']

rule_yaml = 'rule.yaml'
template_yaml = 'clash_template.yaml'
extra_rules_yaml = 'extra_rules.yaml'
extra_proxies_yaml = 'extra_proxies.yaml'
extra_script_shortcut_yaml = 'extra_script_shortcut.yaml'
temp_yaml = configuration['temp_yaml']

local_path = os.path.dirname(__file__)
# out_yaml = local_path + out_yaml
rule_yaml = os.path.join(local_path, rule_yaml)
template_yaml = os.path.join(local_path, template_yaml)
extra_rules_yaml = os.path.join(local_path, extra_rules_yaml)
extra_proxies_yaml = os.path.join(local_path, extra_proxies_yaml)
extra_script_shortcut_yaml = os.path.join(local_path, extra_script_shortcut_yaml)
countries = []
continents_names = {'欧洲': 'Europe',
                    '亚洲': 'Asia',
                    '大洋洲': 'Oceania',
                    '非洲': 'Africa',
                    '北美洲': 'NorthAmerica',
                    '南美洲': 'SouthAmerica'}


class Node:
    def __init__(self):
        self.port = 0
        self.able = False
        self.name = "__default__"

    def print(self):
        pass

    def to_clash(self):
        clash_v2 = {"name": ""}
        return clash_v2

    def parse_link(self, link):
        pass


def is_valid_json(input_string):
    if not input_string:  # Check for empty string or None
        return False
    try:
        json.loads(input_string)
        return True
    except (json.JSONDecodeError, TypeError):
        return False


class V2rayNode(Node):
    def __init__(self):
        super().__init__()
        self.name = ''
        self.host = '0.0.0.0'
        self.type = "vmess"
        self.uuid = ""
        self.udp = True
        self.v2_config = {}

    def parse_link(self, link):
        self.type = link[:5]
        if '@' in link[8:link.find('?')]:
            decode_str = link[8:link.find('?')]
        else:
            base64_encode_str = link[8:link.find('?')]
            decode_str = base64_decode(base64_encode_str)
        query_str = link[link.find('?')+1:]
        if is_valid_json(decode_str):
            self.v2_config = json.loads(decode_str)
        else:
            self.v2_config = {}
            matchObj = re.match(r"(.+:)?(.+)@(.+):(\d+)", decode_str)
            if matchObj is None:
                print(f'Invalid link {link}')
                return
            if matchObj.group(1):
                self.v2_config['cipher'] = matchObj.group(1)[:-1]
            self.uuid = matchObj.group(2)
            self.host = matchObj.group(3)
            self.port = int(matchObj.group(4))
            query_params = parse_qs(query_str[:query_str.rfind('#')])
            self.name = urllib.parse.unquote(query_str[query_str.rfind('#')+1:], 'utf-8')
            if 'alterId' in query_params:
                self.v2_config['alterId'] = int(query_params['alterId'][0])
            if 'remarks' in query_params:
                self.v2_config['remarks'] = query_params['remarks'][0]
            if 'type' in query_params:
                self.v2_config['net'] = query_params['type'][0]
            if 'security' in query_params:
                self.v2_config['tls'] = True
                if query_params['security'][0] == 'reality':
                    self.v2_config['reality-opts'] = {}
            if 'sid' in query_params:
                self.v2_config['reality-opts']['short-id'] = query_params['sid'][0]
            if 'pbk' in query_params:
                self.v2_config['reality-opts']['public-key'] = query_params['pbk'][0]
            if 'sni' in query_params:
                self.v2_config['servername'] = query_params['sni'][0]
            if 'flow' in query_params:
                self.v2_config['flow'] = query_params['flow'][0]
            if 'fp' in query_params:
                self.v2_config['client-fingerprint'] = query_params['fp'][0]
        if 'uuid' in self.v2_config:
            self.uuid = self.v2_config['uuid']
        if 'port' in self.v2_config:
            self.port = self.v2_config['port']
        if 'add' in self.v2_config:
            self.host = self.v2_config['add']
        if 'remarks' in self.v2_config:
            self.name = self.v2_config['remarks']
        self.able = True

    def to_clash(self):
        clash_v2 = {"name": self.name, "type": self.type, "server": self.host, "port": self.port, "uuid": self.uuid,
                    "udp": True, "ip-version": "dual"}
        if self.type == 'vmess':
            clash_v2["network"] = "ws"
            clash_v2["ws-path"] = "/"
            clash_v2["ws-headers"] = {"host": ""}
            clash_v2['uuid'] = self.uuid
            clash_v2['alterId'] = self.v2_config["aid"]
            clash_v2['network'] = self.v2_config["net"]
            clash_v2['ws-headers']['host'] = self.v2_config["add"]
            clash_v2['cipher'] = self.v2_config["cipher"]
        elif self.type == 'vless':
            clash_v2["skip_cert_verify_flag"] = False
            if "net" in self.v2_config:
                clash_v2['network'] = self.v2_config.get("net")
            if "reality-opts" in self.v2_config:
                clash_v2['reality-opts'] = self.v2_config["reality-opts"]
            if "servername" in self.v2_config:
                clash_v2['servername'] = self.v2_config["servername"]
            if "flow" in self.v2_config:
                clash_v2['flow'] = self.v2_config["flow"]
            if "client-fingerprint" in self.v2_config:
                clash_v2['client-fingerprint'] = self.v2_config["client-fingerprint"]
            if "tls" in self.v2_config:
                clash_v2['tls'] = self.v2_config["tls"]
        return clash_v2


class SSNode(Node):
    def __init__(self):
        super().__init__()
        self.method = 'aes-256-cfb'
        self.server = '1.1.1.1'
        self.password = ''

    def parse_link(self, link):
        base64_encode_str = link[5:]
        decode_str = base64_decode(base64_encode_str)
        parts = decode_str.split(':')
        if len(parts) != 3:
            print(f'An error occurred while parsing {link}')
            return
        self.method = parts[0]
        password_and_ip = parts[1]
        self.port = int(parts[2])
        pass_and_server = password_and_ip.split('@')
        self.password = pass_and_server[0]
        self.server = pass_and_server[1]
        self.able = True

    def parse_link2(self, link):
        base64_encode_str = link[5:]
        node_and_name = base64_encode_str.split('#')
        base64_encode_str = node_and_name[0]
        urlencode_str = node_and_name[1]
        self.name = urllib.parse.unquote(urlencode_str)
        decode_str = base64_decode(base64_encode_str)
        parts = decode_str.split(':')
        if len(parts) != 3:
            print(f'An error occurred while parsing {link}')
            return
        self.method = parts[0]
        password_and_ip = parts[1]
        self.port = int(parts[2])
        pass_and_server = password_and_ip.split('@')
        self.password = pass_and_server[0]
        self.server = pass_and_server[1]
        self.able = True

    def encode(self):
        pass

    def to_clash(self):
        clash_ss = {"name": self.name, "type": "ss", "server": self.server, "port": self.port, "cipher": self.method,
                    "password": self.password}
        return clash_ss


class SSRNode(SSNode):
    def __init__(self):
        super().__init__()
        self.protocol = ''
        self.obfs = ''
        self.obfsparam = ''
        self.protoparam = ''
        self.remarks = ''
        self.group = ''

    def parse_link(self, link):
        base64_encode_str = link[6:]
        decode_str = base64_decode(base64_encode_str)
        parts = decode_str.split(':')
        if len(parts) != 6:
            print(f'An error occurred while parsing {link}')
            return
        self.server = parts[0]
        self.port = int(parts[1])
        self.method = parts[3]
        self.protocol = parts[2]
        self.obfs = parts[4]
        password_and_params = parts[5]
        password_and_params = password_and_params.split('/?')
        password_encode_str = password_and_params[0]
        self.password = base64_decode(password_encode_str)
        params = password_and_params[1]
        param_parts = params.split('&')
        param_dict = {}
        for part in param_parts:
            key_and_value = part.split('=')
            param_dict[key_and_value[0]] = key_and_value[1]
        self.name = base64_decode(param_dict['remarks'])
        self.obfsparam = base64_decode(param_dict['obfsparam'])
        self.protoparam = base64_decode(param_dict['protoparam'])
        self.remarks = base64_decode(param_dict['remarks'])
        self.group = base64_decode(param_dict['group'])
        self.able = True

    def encode(self):
        method = self.method
        port = self.port
        server = self.server
        password = base64_encode(self.password)
        protocol = self.protocol
        obfs = self.obfs
        obfsparam = base64_encode(self.obfsparam)
        protoparam = base64_encode(self.protoparam)
        remarks = base64_encode(self.remarks)
        group = base64_encode(self.group)
        decode_str = '%s:%d:%s:%s:%s:%s/?obfsparam=%s&protoparam=%s&remarks=%s&group=%s' % (server, port, protocol,
                                                                                            method, obfs, password,
                                                                                            obfsparam, protoparam,
                                                                                            remarks, group)
        base64_encode_str = base64_encode(decode_str)
        encode_link = 'ssr://' + base64_encode_str
        print(encode_link)
        return encode_link

    def to_clash(self):
        clash_v2 = {"name": self.name, "type": "ssr", "server": self.server, "port": self.port, "cipher": self.method,
                    "password": self.password, "obfs": self.obfs, "protocol": self.protocol,
                    "obfs-param": self.obfsparam, "protocol-param": self.protoparam}
        return clash_v2


class TrojanNode(Node):
    def __init__(self):
        super().__init__()
        # self.method = 'aes-256-cfb'
        self.server = '1.1.1.1'
        self.password = ''
        self.sni = ''
        self.udp = True
        # self.name = ''

    def parse_link(self, link):
        matchObj = re.match(r"trojan://(.+)@(.+):(\d+)\?peer=(.+)#(.*)", link)
        if matchObj is None:
            return
        self.password = matchObj.group(1)
        self.server = matchObj.group(2)
        self.port = int(matchObj.group(3))
        self.sni = matchObj.group(4)
        self.name = urllib.parse.unquote(matchObj.group(5))
        self.able = True

    def encode(self):
        pass

    def to_clash(self):
        clash_ss = {"name": self.name, "type": "trojan", "server": self.server, "port": self.port, "password": self.password,
                    "sni": self.sni, "udp": self.udp}
        return clash_ss


def fill_padding(base64_encode_str):
    need_padding = len(base64_encode_str) % 4 != 0
    if need_padding:
        missing_padding = 4 - need_padding
        base64_encode_str += '=' * missing_padding
    return base64_encode_str


def base64_decode(base64_encode_str):
    base64_encode_str = fill_padding(base64_encode_str)
    return base64.urlsafe_b64decode(base64_encode_str).decode('utf-8')


def replace_padding(base64_encode_str):
    base64_encode_str = base64_encode_str.replace('=', '')
    return base64_encode_str


def base64_encode(base64_decode_str):
    base64_encode_str = base64.urlsafe_b64encode(base64_decode_str.encode('utf-8')).decode('utf-8')
    base64_encode_str = replace_padding(base64_encode_str)
    return base64_encode_str


def parse_subscribe(base64_encode_str):
    s = base64_decode(base64_encode_str)
    tmp = s.split('\n')
    ss_links = []
    for link in tmp:
        if len(link) > 6:
            ss_links.append(link)
    nodes = []
    for ss_link in ss_links:
        node = Node()
        if ss_link.startswith('ss://'):
            node = SSNode()
            node.parse_link2(ss_link)
        elif ss_link.startswith('ssr://'):
            node = SSRNode()
            node.parse_link(ss_link)
        elif ss_link.startswith('vmess://'):
            node = V2rayNode()
            node.parse_link(ss_link)
        elif ss_link.startswith('vless://'):
            node = V2rayNode()
            node.parse_link(ss_link)
        elif ss_link.startswith('trojan://'):
            node = TrojanNode()
            node.parse_link(ss_link)
        if node.able:
            nodes.append(node)
    return nodes


def generate_subscribe(nodes: list):
    links = ''
    for node in nodes:
        ss_link = node.encode()
        links += ss_link
        links += '\n'
    base64_encode_str = base64_encode(links)
    return base64_encode_str


def resolve_server(server):
    addr = socket.getaddrinfo(server, 'http')
    return addr[0][4][0]


def nodes_domain2ip(nodes):
    for node in nodes:
        node.server = resolve_server(node.server)
    sub_str = generate_subscribe(nodes)
    return sub_str


def parsing_domain_name(h):
    hostip = None
    try:
        hostip =socket.gethostbyname(h)
    except socket.error as e:
        print("gethostbyname failed")
    return hostip


def write_log(c) -> None:
    with open(log_path, 'a+', encoding='utf-8') as f:
        f.write(str(c))


def ping_host(ip: str):
    """
    获取节点的延迟的作用
    :param node:
    :return:
    """
    ip_address = ip
    response = ping(ip_address)
    if response is not None:
        delay = int(response * 1000)
        return delay
    return 20000


def continent_name_from_node(node_name: str):
    for country in countries:
        if country['chinese'] in node_name or country['english'] in node_name:
            return continents_names[country['state']]
    return None


if __name__ == "__main__":
    with open('countries_json/countries.json', 'r') as f:
        countries = json.load(f)
    session = requests.session()
    rules = read_yaml(rule_yaml)
    extra_proxies = read_yaml(extra_proxies_yaml)
    clash_config = read_yaml(template_yaml)
    clash_config['rules'] += rules["rules"]
    clash_config['rule-providers'] = rules["rule-providers"]
    for provider in clash_config['rule-providers']:
        clash_config['rule-providers'][provider]['url'] = configuration['rule_providers'][provider]['url']
    user_agent_list = [
        "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36"]
    headers = {"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
               "sec-ch-ua": """"Google Chrome";v="89", "Chromium";v="89", ";Not A Brand";v="99" """,
               "accept-encoding": "gzip, deflate, br",
               "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
               "sec-ch-ua-mobile": "?0",
               "sec-fetch-dest": "document",
               "sec-fetch-mode": "navigate",
               "upgrade-insecure-requests": '1'}
    headers["user-agent"] = user_agent_list[0]
    is_success = False
    userinfo = {"upload": 0, "download": 0, "total": 0, "expire": 0}
    for item in sub_link_list:
        sub_link = item["url"]
        sub_type = item["type"]
        print(sub_link)
        try:
            r = session.get(sub_link, timeout=10, headers=headers)
        except Exception as e:
            barker.bark_notify(f"Failed to get {sub_link}",
                               "Error details",
                               {"Error": f"{e}", 'URL': sub_link},
                               configuration['bark']['group'],
                               'https://raw.githubusercontent.com/walkxcode/dashboard-icons/main/png/cloudflare-pages.png')
            continue
        print("http response code: %d" % r.status_code)
        if r.status_code != 200:
            # exit(-1)
            continue
        # session.close()
        is_success = True
        v2ray_str = r.content.decode('utf-8')
        if 'Subscription-Userinfo' in r.headers:
            matches = re.findall(r'(\w+)=(\d+)', r.headers['Subscription-Userinfo'])
            variables = {key: int(value) for key, value in matches}
            userinfo['download'] = variables['download'] + userinfo['download']
            userinfo['upload'] = variables['upload'] + userinfo['upload']
            userinfo['total'] = variables['total'] + userinfo['total']
            userinfo['expire'] = max(variables['expire'], userinfo['expire'])
        clash_proxy = []
        if sub_type == "clash":
            try:
                clash_sub = yaml.load(v2ray_str, Loader=yaml.FullLoader)
                clash_proxy = clash_sub.get('proxies')
            except Exception as e:
                barker.bark_notify(f"Failed to parse {sub_link} {e}",
                                   'Error details',
                                   {'Error': f'{e}', 'URL': sub_link},
                                   configuration['bark']['group'],
                                   'https://raw.githubusercontent.com/walkxcode/dashboard-icons/main/png/cloudflare-pages.png')
        elif sub_type == "v2ray":
            nodes = parse_subscribe(v2ray_str)
            for v2node in nodes:
                clash_v2 = v2node.to_clash()
                clash_proxy.append(clash_v2)
        for proxy in clash_proxy:
            proxy["ip-version"] = "dual"
            has_kw = False
            for kw in filter_keywords:
                if kw in proxy.get("name", ""):
                    has_kw = True
            if has_kw:
                continue
            clash_config['proxies'].append(proxy)
    continents_nodes = {'Asia': [], 'Europe': [], 'SouthAmerica': [], 'NorthAmerica': [], 'Africa': [], 'Oceania': [], 'Asia except China': []}
    for proxy_node in clash_config['proxies']:
        continent = continent_name_from_node(proxy_node['name'])
        if not continent:
            continue
        continents_nodes[continent].append(proxy_node['name'])
    for continent_nodes in continents_nodes:
        if len(continents_nodes[continent_nodes]):
            proxy_group = {'name': continent_nodes, 'type': 'select', 'proxies': continents_nodes[continent_nodes]}
            clash_config['proxy-groups'].insert(3, proxy_group)

    for continent_node in continents_nodes['Asia']:
        if '中国' in continent_node or '香港' in continent_node:
            continue
        continents_nodes["Asia except China"].append(continent_node)
    proxy_group = {'name': 'Asia except China', 'type': 'select', 'proxies': continents_nodes['Asia except China']}
    clash_config['proxy-groups'].insert(3, proxy_group)
    openai_index = 0
    gemini_index = 0
    index = 0
    for proxy_group in clash_config['proxy-groups']:
        if proxy_group['name'] == 'Openai':
            openai_index = index
        if proxy_group['name'] == 'Gemini':
            gemini_index = index
        index += 1
    openai_auto = []
    for continent_nodes in continents_nodes:
        if continent_nodes != 'Asia' and len(continents_nodes[continent_nodes]):
            clash_config['proxy-groups'][openai_index]['proxies'].insert(0, continent_nodes)
            clash_config['proxy-groups'][gemini_index]['proxies'].insert(0, continent_nodes)
            openai_auto.extend(continents_nodes[continent_nodes])
    proxy_group_ao = {'name': 'Auto Openai',
                      'type': 'url-test',
                      'proxies': openai_auto,
                      'url': 'https://chat.openai.com/',
                      'tolerance': 120,
                      'interval': 300}
    clash_config['proxy-groups'][openai_index]['proxies'].insert(0, proxy_group_ao['name'])
    clash_config['proxy-groups'].insert(openai_index, proxy_group_ao)

    for proxy_node in clash_config['proxies']:
        clash_config['proxy-groups'][0]['proxies'].append(proxy_node['name'])
        clash_config['proxy-groups'][1]['proxies'].append(proxy_node['name'])
        clash_config['proxy-groups'][2]['proxies'].append(proxy_node['name'])
    clash_config['proxies'] += extra_proxies['proxies']
    pt_proxy_group = {'name': 'PTProxy', 'type': "select", 'proxies': ['Proxy', 'DIRECT']}
    for p in clash_config['proxies']:
        pt_proxy_group['proxies'].append(p.get("name"))
    # additional rules
    if is_success:
        clash_config['proxy-groups'].append(pt_proxy_group)
        temp = yaml.dump(userinfo, allow_unicode=True)
        with open(temp_yaml, 'w+', encoding='utf-8') as fl:
            fl.write(temp)
    else:
        prev_clash_config = read_yaml(out_yaml)
        clash_config['proxy-groups'] = prev_clash_config['proxy-groups']
        clash_config['proxies'] = prev_clash_config['proxies']
    extra_rules_dict = read_yaml(extra_rules_yaml)
    extra_rules = extra_rules_dict['rules']
    # extra_script_shortcut = read_yaml(extra_script_shortcut_yaml)
    # clash_config['script']['shortcuts'].update(extra_script_shortcut['shortcuts'])
    clash_config['rules'] = extra_rules + clash_config['rules']
    clash_config_yaml = yaml.dump(clash_config, allow_unicode=True)
    with open(out_yaml, 'w+', encoding='utf-8') as f:
        f.write(clash_config_yaml)
