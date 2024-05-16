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


def read_yaml(path) -> dict:
    with open(path, 'r', encoding='utf-8') as f:
        file_data = f.read()
        rules = yaml.load(file_data, Loader=yaml.FullLoader)
        return rules


if len(sys.argv) < 2:
    print('No configuration file')
    exit(-1)
configuration = read_yaml(sys.argv[1])

filter_keywords = configuration['filter_keywords']
sub_link_list = configuration['subscribe_links']
out_yaml = configuration['out_yaml']
out_local_yaml = configuration['out_local_yaml']
out_without_mitm_yaml = configuration['out_without_mitm_yaml']
log_path = configuration['log_path']

# 测试
# out_yaml = 'clash.yaml'
# out_local_yaml = 'clash_local.yaml'
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
        self.ps = ""
        self.remark = ""
        self.id = ""
        self.v2class = ""

    def parse_link(self, link):
        base64_encode_str = link[8:]
        decode_str = base64_decode(base64_encode_str)
        v2_config = json.loads(decode_str)
        if 'ps' in v2_config:
            self.ps = v2_config['ps']
        else:
            print('error')
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
        if 'remark' in v2_config:
            self.remark = v2_config['remark']
            self.name = self.remark
        if 'id' in v2_config:
            self.id = v2_config['id']
        if 'class' in v2_config:
            self.v2class = v2_config['class']
        self.able = True

    def print(self):
        print(self.host)
        print(self.port)
        print(self.path)
        print(self.tls)
        print(self.verify_cert)
        print(self.add)
        print(self.aid)
        print(self.net)
        print(self.headerType)
        print(self.v)
        print(self.type)
        print(self.ps)
        print(self.remark)
        print(self.id)
        print(self.v2class)

    def to_clash(self):
        clash_v2 = {"name": "", "type": "vmess", "server": "", "port": 0, "uuid": "", "alterId": 0, "cipher": "auto",
                    "udp": True, "network": "ws", "ws-path": "/", "ws-headers": {"host": ""}}
        clash_v2['name'] = self.ps
        clash_v2['server'] = self.add
        clash_v2['port'] = self.port
        clash_v2['uuid'] = self.id
        clash_v2['alterId'] = self.aid
        clash_v2['network'] = self.net
        clash_v2['ws-path'] = self.path
        clash_v2['ws-headers']['host'] = self.add
        return clash_v2


class SSNode(Node):
    def __init__(self):
        super().__init__()
        self.method = 'aes-256-cfb'
        self.server = '1.1.1.1'
        self.password = ''
        # self.name = ''

    def parse_link(self, link):
        base64_encode_str = link[5:]
        decode_str = base64_decode(base64_encode_str)
        parts = decode_str.split(':')
        if len(parts) != 3:
            print('error')
            print(decode_str)
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
            print('error')
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

    def print(self):
        print(self.method)
        print(self.server)
        print(self.password)
        print(self.port)


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
            print('error')
            print(decode_str)
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

    def print(self):
        print(self.method)
        print(self.server)
        print(self.obfs)
        print(self.group)
        print(self.obfsparam)
        print(self.password)
        print(self.port)
        print(self.protocol)
        print(self.protoparam)
        print(self.remarks)

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

    def print(self):
        print(self.server)
        print(self.password)
        print(self.port)


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


def generate_subscribe(nodes):
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
        print(hostip)
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
    clash_config['rule-providers']['proxied_rules']['url'] = configuration['rule_providers']['proxied_rules_url']
    clash_config['rule-providers']['direct_rules']['url'] = configuration['rule_providers']['direct_rules_url']
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
            print(e)
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
    # 附加规则
    extra_rules_dict = read_yaml(extra_rules_yaml)
    extra_rules = extra_rules_dict['rules']
    extra_script_shortcut = read_yaml(extra_script_shortcut_yaml)
    clash_config['script']['shortcuts'].update(extra_script_shortcut['shortcuts'])
    # clash_config['proxies'].append(pt_proxy)
    clash_config['proxy-groups'].append(pt_proxy_group)
    clash_without_mitm_config = clash_config.copy()
    if 'script' in clash_without_mitm_config:
        del clash_without_mitm_config['script']
    extra_rules_without_mitm = []
    for r in extra_rules:
        method = r[(r.rfind(',')) + 1:]
        rule_type = r[:(r.find(','))]
        if rule_type == 'SCRIPT':
            continue
        if method == 'Mitm':
            new_rule = r[:(r.rfind(','))+1] + 'DIRECT'
            extra_rules_without_mitm.append(new_rule)
        else:
            extra_rules_without_mitm.append(r)
    clash_without_mitm_config['rules'] = extra_rules_without_mitm + clash_without_mitm_config['rules']
    clash_config['rules'] = extra_rules + clash_config['rules']
    clash_config_yaml = yaml.dump(clash_config, allow_unicode=True)
    with open(out_yaml, 'w+', encoding='utf-8') as f:
        f.write(clash_config_yaml)

    clash_config_local_yaml = clash_config_yaml.replace('mitmproxy.westsite.cn', '192.168.0.103')
    clash_config_local_yaml = clash_config_local_yaml.replace('s://ptproxy.westsite.cn:7888', '://192.168.0.108:7887')
    with open(out_local_yaml, 'w+', encoding='utf-8') as fl:
        fl.write(clash_config_local_yaml)

    clash_config_without_mitm_yaml = yaml.dump(clash_without_mitm_config, allow_unicode=True)
    with open(out_without_mitm_yaml, 'w+', encoding='utf-8') as fl:
        fl.write(clash_config_without_mitm_yaml)
