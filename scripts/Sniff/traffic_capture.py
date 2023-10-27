#!/usr/bin/python

import configparser
import subprocess
import datetime


def get_formatted_time():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def run_tshark_capture(interface, duration_seconds, report_folder, report_file):
    print(f'[+] [{get_formatted_time()}] Start Tshark traffic sniffing...')
    subprocess.run(
        ['tshark', '-i', interface, '-a', f'duration:{duration_seconds}', '-w', f'{report_folder}/{report_file}'])


def run_tshark_packet_parsing(trafic_file, report_folder, report_file):
    print(f'[+] [{get_formatted_time()}] Start Tshark packet parsing...')
    subprocess.run(
        ['tshark', '-r', trafic_file, '-Y "(mndp || lldp || cdp || ospf || vrrp || llmnr)"', '>>',
         f'{report_folder}/{report_file}'])


if __name__ == "__main__":
    config = configparser.ConfigParser()
    config.read('local_config.ini')

    settings = config['settings']
    report_path = config['report_path']

    interface = settings.get('used_interface')
    duration_seconds = settings.getint('tshark_traffic_capture_time')
    report_folder = report_path.get('sniff_path')

    uniq_filename = datetime.datetime.now().strftime("%Y-%m-%d_%H.%M.%S")
    report_file = f"captured_traffic_{uniq_filename}.pcapng"

    run_tshark_capture(interface, duration_seconds, report_folder, report_file)
    print(f'[+] [{get_formatted_time()}] Tshark traffic sniffing DONE.\n')

    if config.getboolean('settings', 'protocols_parsing'):
        traffic_file = report_folder + '/' + report_file
        packets_report_file = f"captured_packets_{uniq_filename}.log"

        run_tshark_packet_parsing(traffic_file, report_folder, packets_report_file)
        print(f'[+] [{get_formatted_time()}] Packet parsing DONE.\n')
