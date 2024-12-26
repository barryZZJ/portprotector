import psutil
import time
import json
import geoip2.database
import csv
from loguru import logger
from prettytable import PrettyTable
import subprocess
import ipaddress

# Configuration file
CONFIG_FILE = 'config.json'
BANNED_IPS_FILE = 'banned_ips.csv'
WHITELIST_IPS_FILE = 'whitelist_ips.csv'
GEOIP_DB = 'Country.mmdb'  # LoyalSoldier ver: https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb

# Load configuration from JSON file
def load_config():
    with open(CONFIG_FILE, 'r') as f:
        return json.load(f)

# Load banned IPs from CSV file
def load_banned_ips():
    banned_ips = {}
    try:
        with open(BANNED_IPS_FILE, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                banned_ips[row['source_ip']] = {
                    'source_ip': row['source_ip'],
                    'source_port': int(row['source_port']),
                    'target_port': int(row['target_port']),
                    'tried_count': int(row['tried_count']),
                    'country': row['country']
                }
                block_ip(row['source_ip'], int(row['target_port']))
    except FileNotFoundError:
        save_banned_ips(banned_ips)
    return banned_ips

# Load whitelist IPs from CSV file and unblock them
def load_whitelist_ips():
    whitelist_ips = {}
    try:
        with open(WHITELIST_IPS_FILE, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                whitelist_ips[row['source_ip']] = {
                    'source_ip': row['source_ip'],
                    'target_port': int(row['target_port'])
                }
                unblock_ip(row['source_ip'], int(row['target_port']))
    except FileNotFoundError:
        save_whitelist_ips(whitelist_ips)
    return whitelist_ips

# Save banned IPs to CSV file
def save_banned_ips(banned_ips):
    with open(BANNED_IPS_FILE, 'w', newline='') as f:
        fieldnames = ["source_ip", "source_port", "target_port", "tried_count", "country"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for ip, info in banned_ips.items():
            writer.writerow({
                'source_ip': info['source_ip'],
                'source_port': info['source_port'],
                'target_port': info['target_port'],
                'tried_count': info['tried_count'],
                'country': info['country']
            })

def save_whitelist_ips(whitelist_ips):
    with open(WHITELIST_IPS_FILE, 'w', newline='') as f:
        fieldnames = ["source_ip", "target_port"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for ip, info in whitelist_ips.items():
            writer.writerow({
                'source_ip': info['source_ip'],
                'target_port': info['target_port']
            })

# Get geographical location of an IP
def get_country(ip):
    with geoip2.database.Reader(GEOIP_DB) as reader:
        response = reader.country(ip)
        return response.country.names['zh-CN']

# Display banned IPs in a table format
def display_banned_ips(banned_ips):
    # os.system('clear')
    table = PrettyTable()
    table.field_names = ["Source IP", "Source Port", "Target Port", "Tried Count", "Country"]
    # current_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    for ip, info in banned_ips.items():
        table.add_row([
            info['source_ip'],
            info['source_port'],
            info['target_port'],
            info['tried_count'],
            info['country']
        ])
    # print(current_time)
    print(table)

# Block IP using ufw
def block_ip(ip, target_port):
    subprocess.run(['ufw', 'deny', 'from', ip, 'to', 'any', 'port', str(target_port)])

# Unblock IP using ufw
def unblock_ip(ip, target_port):
    subprocess.run(['ufw', 'delete', 'deny', 'from', ip, 'to', 'any', 'port', str(target_port)])

# Convert IPv4-mapped IPv6 address to IPv4
def convert_to_ipv4(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.version == 6 and ip_obj.ipv4_mapped:
            return str(ip_obj.ipv4_mapped)
    except ValueError:
        pass
    return ip

# Monitor connections on specified ports
def monitor_ports(config, banned_ips, whitelist_ips):
    logger.info("Monitoring ports: " + str(config['PORTS']))
    records = {}  # type: dict[str, list[int, int]]  # IP: [last tried port, count]
    for i in range(config['SCAN_DURATION']//config['SCAN_INTERVAL']):
        logger.info(f"Checking loop {i+1}/{config['SCAN_DURATION']//config['SCAN_INTERVAL']}")
        connections = psutil.net_connections(kind='tcp')
        for conn in connections:
            if conn.laddr.port in config['PORTS'] and conn.status == 'ESTABLISHED':
                ip = convert_to_ipv4(conn.raddr.ip)

                # Skip existed IPs
                if ip in whitelist_ips or ip in banned_ips:
                    continue

                source_port = conn.raddr.port
                target_port = conn.laddr.port

                # Check if the connection is from a different source port
                if records.setdefault(ip, [-1, 0])[0] != source_port:
                    records[ip][0] = source_port  # last tried port
                    records[ip][1] += 1  # count
                    logger.info(f"Connection from {ip}:{source_port} to port {target_port} ({records[ip][1]} times)")

                if records[ip][1] >= config['THRESHOLD']:
                    # add to ban list
                    logger.info(f"Blocking {ip} for accessing port {target_port}")
                    block_ip(ip, target_port)  # Block the IP with target port
                    banned_ips[ip] = {
                        'source_ip': ip,
                        'source_port': source_port,
                        'target_port': target_port,
                        'tried_count': records[ip][1],
                        'country': get_country(ip)
                    }
                    save_banned_ips(banned_ips)

        # display_banned_ips(banned_ips)
        time.sleep(config['SCAN_INTERVAL'])
    logger.info("Exiting...")
    display_banned_ips(banned_ips)

# Main function
def main():
    config = load_config()
    banned_ips = load_banned_ips()
    whitelist_ips = load_whitelist_ips()

    monitor_ports(config, banned_ips, whitelist_ips)

if __name__ == "__main__":
    main()