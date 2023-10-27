#!/usr/bin/python

import configparser
import schedule
import time
import subprocess


def backconnect_shell():
    subprocess.run(['python', './scripts/Shell/backconnect.py'])


if __name__ == "__main__":
    config = configparser.ConfigParser()
    config.read('local_config.ini')

    if config.getboolean('settings', 'back_connect_shell'):
        timeout = config.getint('settings', 'back_connect_shell_timeout')
        schedule.every(timeout).minutes.do(backconnect_shell)

    while True:
        schedule.run_pending()
        time.sleep(1)