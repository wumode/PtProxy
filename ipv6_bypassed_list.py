import yaml
import socket
import requests
import sys
import ipaddress

chnroute6_lists_URL = 'https://ispip.clang.cn/all_cn_ipv6.txt'


def is_ip_in_subnet(ip: str, subnet: str) -> bool:
    """
    Check if the given IP address is in the specified subnet.

    :param ip: IP address as a string (e.g., '192.168.1.1')
    :param subnet: Subnet in CIDR notation (e.g., '192.168.1.0/24')
    :return: True if IP is in the subnet, False otherwise
    """
    ip_obj = ipaddress.ip_address(ip)
    subnet_obj = ipaddress.ip_network(subnet, strict=False)
    return ip_obj in subnet_obj


def doh_dns_lookup(domain, query_type):
    # query_type:
    # A	    1	IPv4 地址
    # NS	2	NS 记录
    # CNAME	5	域名 CNAME 记录
    # SOA	6	ZONE 的 SOA 记录
    # TXT	16	TXT 记录
    # AAAA	28	IPv6 地址
    url = 'https://dns.alidns.com/resolve'
    params = {
        'name': domain,
        'type': query_type,
    }
    headers = {
        'Accept': 'application/dns-json'
    }

    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()  # Raise an exception for HTTP errors

        data = response.json()
        return  [answer['data'] for answer in data.get('Answer', [])]


    except requests.RequestException as e:
        print(f"An error occurred: {e}")
        return None


def main():
    # Load domains from YAML file
    with open(sys.argv[1], 'r') as file:
        data = yaml.safe_load(file)
    domains = data.get('domains', [])
    ips = data.get('ips', [])
    replacing = data.get('replace')

    # Load Chnroute6 Lists
    r = requests.get(chnroute6_lists_URL, timeout=10)
    chnroute6_lists = r.content.decode('utf-8')[:-1].split('\n')
    new_list = []

    # replace ips
    for ipr in chnroute6_lists:
        if ipr in replacing:
            for replacing_ip in replacing[ipr]:
                new_list.append(replacing_ip)
        else:
            new_list.append(ipr)
    # for ip in ips:
    #     new_list.append(ip)
    for domain in domains:
        ipv6_addresses = doh_dns_lookup(domain, 'AAAA')
        if not ipv6_addresses:
            print(domain)
            continue
        for address in ipv6_addresses:
            has_flag = False
            for subnet in new_list:
                if is_ip_in_subnet(address, subnet):
                    has_flag = True
                    break
            if not has_flag:
                new_list.append(ipaddress.ip_network(f"{address}/64", strict=False))
    print(f'write bypassed list into {sys.argv[2]}')
    with open(sys.argv[2], 'w') as file:
        for i in new_list:
            file.write(f'{i}\n')


if __name__ == "__main__":
    main()
