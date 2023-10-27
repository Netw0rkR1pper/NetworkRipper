#!/usr/bin/python

import subprocess
import nmap
import datetime
import ipaddress
import os
import configparser

device_ports = [
    21, 22, 23, 80, 81, 88, 443, 554, 555, 2280, 6667, 7070, 7447, 8080, 8081, 8090, 8443, 8554, 8888, 10554
]


def get_formatted_time():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def run_routersploit(target_ip, log_file):
    command = f"routersploit -m scanners/autopwn -s 'target {target_ip}'"

    try:
        with open(log_file, "a") as log:
            result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
            log.write(result)
    except subprocess.CalledProcessError as e:
        print("[-] Error running routersploit: {e.output}")
    except Exception as e:
        print(f"[-] Error: {e}")


def get_network_devices(target, ports):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, ports=f'{",".join(map(str, ports))}')
    return nm.all_hosts()


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


if __name__ == "__main__":

    config = configparser.ConfigParser()
    config.read('local_config.ini')

    report_folder = config.get('report_path', 'attacks_path')
    log_file = f"{report_folder}/rsf_autopwn.log"

    interface = config.get('settings', 'used_interface')
    ip_address = get_local_ip(interface)
    target_network = generate_subnet(ip_address)

    targets = get_network_devices(target_network, device_ports)
    print(f'\n[+] [{get_formatted_time()}] Start Routersploit testing...')
    for host in targets:
        run_routersploit(host, log_file)

    if os.path.isfile("routersploit.log"):
        try:
            os.remove("routersploit.log")
        except Exception as e:
            print(f"[-] Error deleting log file routersploit.log: {e}")

    print(f'\n[+] [{get_formatted_time()}] Routersploit testing DONE.')
