#!/usr/bin/python

import os
import time
import subprocess
import configparser
import datetime


def get_formatted_time():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_local_ip(interface='eth0'):
    cmd = f"ip addr show {interface} | grep 'inet ' | awk '{{print $2}}'"
    output = os.popen(cmd).read().strip()
    return output.split('/')[0]


def check_ip_address(interface):
    while True:
        result = subprocess.run(["ip", "addr", "show", "dev", interface], capture_output=True, text=True)
        output = result.stdout

        if "inet " in output:
            break

        time.sleep(5)
        subprocess.run("pkexec dhclient", shell=True, capture_output=True, text=True)


def start_ssh_service():
    try:
        subprocess.run(['sudo', 'systemctl', 'start', 'ssh'])
    except Exception as e:
        print(f"[-] [{get_formatted_time()}] Error starting SSH service: {str(e)}")


if __name__ == "__main__":
    config = configparser.ConfigParser()
    config.read('local_config.ini')

    interface = config.get('settings', 'used_interface')
    check_ip_address(interface)
    local_ip = get_local_ip(interface)

    if config.getboolean('settings', 'bind_ssh_shell'):
        start_ssh_service()

    if config.getboolean('settings', 'network_scan'):
        subprocess.run(['python', './scripts/Information_Gathering/scan.py'])

    if config.getboolean('settings', 'tshark_traffic_sniffing'):
        subprocess.run(['python', './scripts/Sniff/traffic_capture.py'])

    if config.getboolean('settings', 'credslayer_traffic_sniffing'):
        subprocess.run(['python', './scripts/Sniff/credslayer_capture.py'])

    if config.getboolean('settings', 'metasploit_autopwn'):
        subprocess.run(['python', './scripts/Attack/msf_autopwn.py'])

    if config.getboolean('settings', 'routersploit_autopwn'):
        subprocess.run(['python', './scripts/Attack/rsf_autopwn.py'])

    if config.getboolean('settings', 'send_report_to_ssh_server'):
        subprocess.run(['python', './send_report.py'])
