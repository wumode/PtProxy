import yaml
import socket
import requests
import sys
import ipaddress

chnroute6_lists_url = 'https://ispip.clang.cn/all_cn_ipv6.txt'
chnroute_lists_url = 'https://ispip.clang.cn/all_cn.txt'
china_ip_route = True
china_ipv6_route = True


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
        return [answer['data'] for answer in data.get('Answer', []) if answer.get('type') == 28 or answer.get('type') == 1]

    except requests.RequestException as e:
        print(f"An error occurred: {e}")
        return []


def resolve_domain(domain_name):
    try:
        # Get address info for both IPv4 and IPv6
        addr_info = socket.getaddrinfo(domain_name, None, socket.AF_UNSPEC, socket.SOCK_STREAM)

        ipv4_addresses = []
        ipv6_addresses = []

        # Iterate over the address info
        for info in addr_info:
            # Address info is a tuple: (family, type, proto, canonname, sockaddr)
            # We're interested in the sockaddr which contains the actual IP address
            ip_address = info[4][0]

            # Check if the IP address is IPv4 or IPv6
            if '.' in ip_address:
                ipv4_addresses.append(ip_address)
            elif ':' in ip_address:
                ipv6_addresses.append(ip_address)
        # print(f"IPv4 addresses of {domain_name}: {ipv4_addresses}")
        # print(f"IPv6 addresses of {domain_name}: {ipv6_addresses}")
        return [domain_name, ipv4_addresses, ipv6_addresses]

    except socket.gaierror as e:
        return None


def search_ip(ip, ips_list):
    i = 0
    for ip_range in ips_list:
        if is_ip_in_subnet(ip, ip_range):
            return i
        i += 1
    return -1


def main():
    # Load domains from YAML file
    with open(sys.argv[1], 'r') as file:
        data = yaml.safe_load(file)
    domains = data.get('domains', [])
    ips = data.get('ips', [])
    replacing = data.get('replace')
    exempt_domains = data.get('exempt_domains', [])

    ipv6_list = []
    ip_list = []
    if china_ipv6_route:
        # Load Chnroute6 Lists
        r = requests.get(chnroute6_lists_url, timeout=10)
        chnroute6_lists = r.content.decode('utf-8')[:-1].split('\n')
        # replace ips
        for ipr in chnroute6_lists:
            if ipr in replacing:
                for replacing_ip in replacing[ipr]:
                    ipv6_list.append(replacing_ip)
            else:
                ipv6_list.append(ipr)
    if china_ip_route:
        # Load Chnroute Lists
        r = requests.get(chnroute_lists_url, timeout=10)
        chnroute_lists = r.content.decode('utf-8')[:-1].split('\n')
        for ipr in chnroute_lists:
            ip_list.append(ipr)
    for domain in domains:
        ipv6_addresses = doh_dns_lookup(domain, 'AAAA')
        for address in ipv6_addresses:
            has_flag = False
            for subnet in ipv6_list:
                if is_ip_in_subnet(address, subnet):
                    has_flag = True
                    break
            if not has_flag:
                ipv6_list.append(ipaddress.ip_network(f"{address}/128", strict=False))

        ip_addresses = doh_dns_lookup(domain, 'A')
        for address in ip_addresses:
            has_flag = False
            for subnet in ip_list:
                if is_ip_in_subnet(address, subnet):
                    has_flag = True
                    break
            if not has_flag:
                ip_list.append(f"{address}/32")

    # add ips
    for subnet in ips:
        ip_obj = ipaddress.ip_address(subnet[:subnet.rfind('/')])
        if isinstance(ip_obj, ipaddress.IPv4Address):
            ip_list.append(subnet)
        elif isinstance(ip_obj, ipaddress.IPv6Address):
            ipv6_list.append(subnet)

    # remove exempt domain names
    for domain in exempt_domains:
        ip_res = resolve_domain(domain)
        if not ip_res:
            continue
        for ip in ip_res[1]:
            index = search_ip(ip, ip_list)
            if index != -1:
                print(f'exempt {domain}({ip}) from {ip_list[index]}')
                ip_list.pop(index)
        for ip in ip_res[2]:
            index = search_ip(ip, ipv6_list)
            if index != -1:
                print(f'exempt {domain}({ip}) from {ip_list[index]}')
                ipv6_list.pop(index)

    print(f'write bypassed list into {sys.argv[2]}')
    with open(sys.argv[2], 'w') as file:
        for i in ip_list:
            file.write(f'{i}\n')
    print(f'write ipv6 bypassed list into {sys.argv[3]}')
    with open(sys.argv[3], 'w') as file:
        for i in ipv6_list:
            file.write(f'{i}\n')


if __name__ == "__main__":
    main()
