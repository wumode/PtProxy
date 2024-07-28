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
from bark import bark_sender


def read_yaml(path) -> dict:
    with open(path, 'r', encoding='utf-8') as f:
        file_data = f.read()
        rules = yaml.load(file_data, Loader=yaml.FullLoader)
        return rules


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
        self.host = ''
        self.path = ""
        self.tls = ""
        self.verify_cert = False
        self.add = ""
        self.aid = ""
        self.net = "ws"
        self.headerType = "none"
        self.v = "2"
        self.type = "none"
        self.uuid = ""
        self.remarks = ""
        self.v2class = ""
        self.cipher = 'auto'
        self.udp = True
        self.alterId = 0
        self.name = ''

    def parse_link(self, link):
        base64_encode_str = link[8:link.find('?')]
        decode_str = base64_decode(base64_encode_str)
        query_str = link[link.find('?')+1:]
        if is_valid_json(decode_str):
            v2_config = json.loads(decode_str)
        else:
            v2_config = {}
            matchObj = re.match(r"(.+):(.+)@(.+):(\d+)", decode_str)
            if matchObj is None:
                return
            v2_config['cipher'] = matchObj.group(1)
            v2_config['uuid'] = matchObj.group(2)
            v2_config['add'] = matchObj.group(3)
            v2_config['port'] = int(matchObj.group(4))
            query_params = parse_qs(query_str)
            if 'alterId' in query_params:
                v2_config['alterId'] = int(query_params['alterId'][0])
            if 'remarks' in query_params:
                v2_config['remarks'] = query_params['remarks'][0]
                v2_config['name'] = query_params['remarks'][0]
        if 'uuid' in v2_config:
            self.uuid = v2_config['uuid']
        else:
            print(f'An error occurred while parsing {link}')
            return
        if 'host' in v2_config:
            self.host = v2_config['host']
        if 'port' in v2_config:
            self.port = v2_config['port']
        if 'path' in v2_config:
            self.path = v2_config['path']
        if 'tls' in v2_config:
            self.tls = v2_config['tls']
        if 'verify_cert' in v2_config:
            self.verify_cert = v2_config['verify_cert']
        if 'add' in v2_config:
            self.add = v2_config['add']
        if 'aid' in v2_config:
            self.aid = v2_config['aid']
        if 'net' in v2_config:
            self.net = v2_config['net']
        if 'headerType' in v2_config:
            self.headerType = v2_config['headerType']
        if 'v' in v2_config:
            self.v = v2_config['v']
        if 'type' in v2_config:
            self.type = v2_config['type']
        if 'remarks' in v2_config:
            self.remarks = v2_config['remarks']
            self.name = self.remarks
        if 'class' in v2_config:
            self.v2class = v2_config['class']
        if 'alterId' in v2_config:
            self.alterId = v2_config['alterId']
        self.able = True

    def to_clash(self):
        clash_v2 = {"name": "", "type": "vmess", "server": "", "port": 0, "uuid": "", "alterId": 0, "cipher": "auto",
                    "udp": True, "network": "ws", "ws-path": "/", "ws-headers": {"host": ""}}
        clash_v2['name'] = self.name
        clash_v2['server'] = self.add
        clash_v2['port'] = self.port
        clash_v2['uuid'] = self.uuid
        clash_v2['alterId'] = self.aid
        clash_v2['network'] = self.net
        clash_v2['ws-path'] = self.path
        clash_v2['ws-headers']['host'] = self.add
        clash_v2['alterId'] = self.alterId
        clash_v2['cipher'] = self.cipher
        clash_v2['udp'] = self.udp
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


class TorjanNode(Node):
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
        elif ss_link.startswith('trojan://'):
            node = TorjanNode()
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
        if country['country_cname'] in node_name:
            return continents_names[country['continent_cname']]
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
    clash_config['rule-providers']['proxied_rules']['url'] = configuration['rule_providers']['proxied_rules']['url']
    clash_config['rule-providers']['direct_rules']['url'] = configuration['rule_providers']['direct_rules']['url']
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
    headers['user-agent'] = user_agent_list[0]
    is_success = False
    userinfo = {'upload': 0, 'download': 0, 'total': 0, 'expire': 0}
    for sub_link in sub_link_list:
        print(sub_link)
        try:
            r = session.get(sub_link, timeout=10, headers=headers)
        except Exception as e:
            barker.bark_notify(f'Failed to get {sub_link}',
                               'Error details',
                               {'Error': f'{e}', 'URL': sub_link},
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

        nodes = parse_subscribe(v2ray_str)
        clash_Proxy = []
        clash_Proxy_names = []
        for v2node in nodes:
            has_kw = False
            for kw in filter_keywords:
                if kw in v2node.name:
                    has_kw = True
            if has_kw:
                continue
            clash_v2 = v2node.to_clash()
            clash_Proxy.append(clash_v2)
            clash_Proxy_names.append(clash_v2['name'])

        clash_config['proxies'] += clash_Proxy
    if not is_success:
        exit(1)
    temp = yaml.dump(userinfo, allow_unicode=True)
    with open(temp_yaml, 'w+', encoding='utf-8') as fl:
        fl.write(temp)

    continents_nodes = {'Asia': [], 'Europe': [], 'SouthAmerica': [], 'NorthAmerica': [], 'Africa': [], 'Oceania': [], 'Asia expect china': []}
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
        continents_nodes['Asia expect china'].append(continent_node)
    proxy_group = {'name': 'Asia expect china', 'type': 'select', 'proxies': continents_nodes['Asia expect china']}
    clash_config['proxy-groups'].insert(3, proxy_group)
    openai_index = 0
    for proxy_group in clash_config['proxy-groups']:
        if proxy_group['name'] == 'Openai':
            break
        openai_index += 1
    openai_auto = []
    for continent_nodes in continents_nodes:
        if continent_nodes != 'Asia' and len(continents_nodes[continent_nodes]):
            clash_config['proxy-groups'][openai_index]['proxies'].insert(0, continent_nodes)
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
    pt_proxy_group = {'name': 'PTProxy', 'type': "select", 'proxies': ['LoadBalance', 'DIRECT']}
    # additional rules
    extra_rules_dict = read_yaml(extra_rules_yaml)
    extra_rules = extra_rules_dict['rules']
    extra_script_shortcut = read_yaml(extra_script_shortcut_yaml)
    clash_config['script']['shortcuts'].update(extra_script_shortcut['shortcuts'])
    clash_config['proxy-groups'].append(pt_proxy_group)

    clash_config['rules'] = extra_rules + clash_config['rules']
    clash_config_yaml = yaml.dump(clash_config, allow_unicode=True)
    with open(out_yaml, 'w+', encoding='utf-8') as f:
        f.write(clash_config_yaml)
