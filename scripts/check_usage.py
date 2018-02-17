#!/usr/bin/env python
# The first fork accomplishes two things - allow the shell to return, and allow you to do a setsid().
#
# The setsid() removes yourself from your controlling terminal. You see, before, you were still listed
# as a job of your previous process, and therefore the user might accidentally send you a signal.
# setsid() gives you a new session, and removes the existing controlling terminal.
#
# The problem is, you are now a session leader. As a session leader, if you open a file descriptor that is a terminal,
# it will become your controlling terminal (oops!). Therefore, the second fork makes you NOT be a session leader.
# Only session leaders can acquire a controlling terminal, so you can open up any file you wish
# without worrying that it will make you a controlling terminal.
#
# So - first fork - allow shell to return, and permit you to call setsid()
#
# Second fork - prevent you from accidentally reacquiring a controlling terminal.

import os, time, re
import subprocess
import json
import requests
import logging
from datetime import datetime
from daemonize import daemonize


def get_syslevel_iptables():
    iptables = {}
    ip = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    out = subprocess.Popen("/sbin/iptables -nvxL", shell=True, stdout=subprocess.PIPE)
    result = (out.stdout.read()).split('\n')
    for line in result:
        if (ip.search(line)):
            byte_count = line[1]
            src_ip = line[7]
            dest_ip = line[8]
            if (src_ip == '0.0.0.0/0' and dest_ip != '0.0.0.0/0' and dest_ip != '255.255.255.255.')
                iptables[dest_ip] += byte_count
    return iptables


if __name__ == '__main__':
    iptables = {}
    iptables = get_syslevel_iptables()
    if len(iptables) > 0:
        update_iptables_into_db()
        # find mac address and chec
        # ip exceeding data usage
        # db insert into iptables
        # ips not in iptables table 
    #daemonize(stdout='/tmp/stdout.log', stderr='/tmp/stderr.log')
