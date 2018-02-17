#!/usr/bin/env python

import sys
import re
import logging
import subprocess
import requests
import json
from datetime import datetime
import time
from socket import *
import MySQLdb



def insert_ip_into_sys_iptables(ip):
    ipt_rule_src = '/sbin/iptables -I FORWARD -s ' + ip + ' -j ACCEPT'
    ipt_rule_dsc = '/sbin/iptables -I FORWARD -d ' + ip + ' -j ACCEPT'
    out = subprocess.Popen(ipt_rule_src, shell=True, stdout=subprocess.PIPE)
    out = subprocess.Popen(ipt_rule_dsc, shell=True, stdout=subprocess.PIPE)



if __name__ == '__main__':
    logging.basicConfig(filename='/var/spool/squid/squid-redirect.log', level=logging.DEBUG)
    insert_ip_into_sys_iptables('10.0.0.100')

