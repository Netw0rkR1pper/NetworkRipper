#!/usr/bin/python

import ipaddress
import subprocess
import configparser
import datetime
import argparse
import os
import nmap

vulnerability_data = [
    {
        'name': 'ms17_010_eternalblue',
        'exploit_module': 'exploit/windows/smb/ms17_010_eternalblue',
        'payload_module': 'payload/generic/shell_reverse_tcp',
        'log_file': 'ms17_010_eternalblue.log'
    },
    {
        'name': 'ms08_067_netapi',
        'exploit_module': 'exploit/windows/smb/ms08_067_netapi',
        'payload_module': 'payload/generic/shell_reverse_tcp',
        'log_file': 'ms08_067_netapi.log'
    },
    {
        'name': 'cve_2021_1675_printnightmare',
        'exploit_module': 'exploit/windows/dcerpc/cve_2021_1675_printnightmare',
        'payload_module': 'payload/generic/shell_reverse_tcp',
        'log_file': 'cve_2021_1675_printnightmare.log'
    },
    {
        'name': 'cve_2020_0796_smbghost',
        'exploit_module': 'exploit/windows/smb/cve_2020_0796_smbghost',
        'payload_module': 'payload/generic/shell_reverse_tcp',
        'log_file': 'cve_2020_0796_smbghost.log'
    },
    {
        'name': 'cve_2019_0708_bluekeep_rce',
        'exploit_module': 'exploit/windows/rdp/cve_2019_0708_bluekeep_rce',
        'payload_module': 'payload/generic/shell_reverse_tcp',
        'log_file': 'cve_2019_0708_bluekeep_rce.log'
    }
]

vulnerable_hosts_file = 'vulnerable_hosts.txt'

windows_ports = [135, 139, 445, 3389]


def get_formatted_time():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_local_ip(interface='eth0'):
    cmd = f"ip addr show {interface} | grep 'inet ' | awk '{{print $2}}'"
    output = os.popen(cmd).read().strip()
    return output.split('/')[0]


def generate_subnet(ip_address, prefix_length=24):
    try:
        ip = ipaddress.IPv4Address(ip_address)
        subnet = ipaddress.IPv4Network(f"{ip}/{prefix_length}", strict=False)
        return str(subnet)
    except Exception as e:
        return None


def get_network_devices(target, ports):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, ports=f'{",".join(map(str, ports))}')
    return nm.all_hosts()


def run_msfcommand_and_save_to_log(vulnerability, rhosts, report_folder):
    try:
        command = f'msfconsole -q -x "use {vulnerability["exploit_module"]}; set rhosts {rhosts}; set payload {vulnerability["payload_module"]}; check; exit;"'

        log_file = f"{report_folder}/{vulnerability['log_file']}"
        vulnerable_report = f"{report_folder}/{vulnerable_hosts_file}"

        with open(log_file, 'a') as file, open(vulnerable_report, 'a') as vuln_file:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in process.stdout:
                file.write(line)
                if "The target is vulnerable" in line:
                    print(f"\n{vulnerability['name']} | {line}")
                    vuln_file.write(f"{vulnerability['name']} | {line}")
            process.wait()
            return True
    except Exception as e:
        print(f"[-] Error running msfconsole: {e}")
        return False


def start_vulnerabilities_test(ip_addresses, report_folder):
    for vulnerability in vulnerability_data:
        print(f"[+] [{get_formatted_time()}] Testing {vulnerability['name']}:")
        for ip_address in ip_addresses:
            if not run_msfcommand_and_save_to_log(vulnerability, ip_address, report_folder):
                print(f"[-] Error running msfconsole for {vulnerability['name']} on {ip_address}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vulnerability Testing Script")
    parser.add_argument("--ips", help="List of IP addresses to test (comma-separated)")
    args = parser.parse_args()

    config = configparser.ConfigParser()
    config.read('local_config.ini')
    report_folder = config.get('report_path', 'attacks_path')

    if args.ips:
        targets = [ip.strip() for ip in args.ips.split(',')]
    else:
        interface = config.get('settings', 'used_interface')
        ip_address = get_local_ip(interface)
        target_network = generate_subnet(ip_address)
        targets = get_network_devices(target_network, windows_ports)

    print(f'\n[+] [{get_formatted_time()}] Start Vulnerability testing...')
    start_vulnerabilities_test(targets, report_folder)
    print(f'[+] [{get_formatted_time()}] Vulnerability testing DONE.\n')
