#!/usr/bin/python

import os
import subprocess
import time
import nmap
import configparser
import datetime


def get_uniq_filename():
    return datetime.datetime.now().strftime("%Y-%m-%d_%H.%M.%S")


def get_formatted_time():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_local_ip(interface='eth0'):
    cmd = f"ip addr show {interface} | grep 'inet ' | awk '{{print $2}}'"
    output = os.popen(cmd).read().strip()
    return output.split('/')[0]


def scan_network(ip):
    nm = nmap.PortScanner()
    scan_result = nm.scan(hosts=f"{ip}/24", arguments='-F -O')

    report_folder = config.get('report_path', 'network_information_path')
    report_file = "network_scan_report_{}.json".format(uniq_filename)
    with open(report_folder + '/' + report_file, 'w') as file:
        file.write(str(scan_result))

    report = f"Scan Report for {ip}\n\n"
    for host in scan_result['scan']:
        report += f"Host: {host}\n"
        if 'addresses' in scan_result['scan'][host] and 'mac' in scan_result['scan'][host]['addresses']:
            report += f"MAC: {scan_result['scan'][host]['addresses']['mac']}\n"
        if 'osmatch' in scan_result['scan'][host] and len(scan_result['scan'][host]['osmatch']) > 0:
            report += f"OS: {scan_result['scan'][host]['osmatch'][0]['name']}"
            report += f" ({scan_result['scan'][host]['osmatch'][0]['osclass'][0]['vendor']}"
            report += f" {scan_result['scan'][host]['osmatch'][0]['osclass'][0]['osfamily']}"
            report += f" {scan_result['scan'][host]['osmatch'][0]['osclass'][0]['osgen']})\n"
        if 'tcp' in scan_result['scan'][host]:
            for port in scan_result['scan'][host]['tcp']:
                state = scan_result['scan'][host]['tcp'][port]['state']
                service = scan_result['scan'][host]['tcp'][port]['name']
                product = scan_result['scan'][host]['tcp'][port]['product']
                version = scan_result['scan'][host]['tcp'][port]['version']
                report += f"  Port: {port}/{state}\n"
                report += f"    Service: {service}\n"
                report += f"    Product: {product}\n"
                report += f"    Version: {version}\n"

            report += "\n"

    return report


def check_ip_address(interface):
    while True:
        result = subprocess.run(["ip", "addr", "show", "dev", interface], capture_output=True, text=True)
        output = result.stdout

        if "inet " in output:
            break

        time.sleep(5)
        result2 = subprocess.run("pkexec dhclient", shell=True, capture_output=True, text=True)


if __name__ == "__main__":
    config = configparser.ConfigParser()
    config.read('local_config.ini')

    uniq_filename = get_uniq_filename()

    # get interface from config
    interface = config.get('settings', 'used_interface')
    # wait until the interface receives the address
    check_ip_address(interface)
    # get local ip
    local_ip = get_local_ip(interface)

    print(f'[+] [{get_formatted_time()}] Scanning network...')
    report = scan_network(local_ip)
    report_folder = config.get('report_path', 'network_information_path')
    report_file = "network_scan_report_{}.txt".format(uniq_filename)
    with open(report_folder + '/' + report_file, 'w') as file:
        file.write(report)

    print(f'[+] [{get_formatted_time()}] Scan completed. The results have been saved in {report_folder}/{report_file}\n')
