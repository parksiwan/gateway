#!/usr/bin/env python

import os, sys
import re
import logging
import subprocess
import requests
import json
from datetime import datetime
from daemonize import daemonize
import time
from socket import *
import MySQLdb


def redirect_url():
    db = MySQLdb.connect(host="127.0.0.1", user="root", passwd="psw1101714", db="gateway")
    cur = db.cursor()
    
    found_mac = 0;
    while True:
        request = sys.stdin.readline()
        logging.debug(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '(req)'+ request  + '\n')
        [ch_id, url, ipaddr, method, user] = request.split()
        logging.debug(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '(user)'+ user  + '\n')

        #if 'detectportal' in url or 'ocsp' in url:    # takes user to login page for registration or login
        #    continue
        
        mac = get_mac_address(ipaddr)
        if mac != ' ':
            # ---> authenticate mac with local db
            found_mac  = authenticate_mac_with_local_db(db, cur, mac, ipaddr)
            # ---> authenticate mac with remote auth server
            #found_mac  = authenticate_mac_with_auth_server(mac)
        logging.debug(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '(found_mac)'+ str(found_mac)  + '\n')

        response  = ch_id + ' OK'
        if (found_mac == 1):    # Later, for this mac set qos profile to normal otherwise shaping
            response += ' status=200 url='
            response += url
            response += '\n'
            sys.stdout.write(response)
            sys.stdout.flush()
            logging.debug(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + ': (res)' + response + '\n')
            continue


        if 'mywifiait' in url:    # takes user to login page for registration or login
            response += ' status=302 url=https://gateway-parksiwan.c9users.io/login.php?mac='
            response += mac
            response += '\n'
            sys.stdout.write(response)
            sys.stdout.flush()
            logging.debug(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + ': (res)' + response + '\n')
            continue

        #response += ' status=200 url='
        response += ' status=302 url=https://gateway-parksiwan.c9users.io/login.php?mac='
        response += mac
        response += '\n'
        sys.stdout.write(response)
        sys.stdout.flush()
        logging.debug(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + ': (res)' + response + '\n')
    db.close()
    cur.close()
    
def authenticate_mac_with_local_db(db, cur, mac_address, ip_address):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    # ---> authenticate mac with local db
    # The following is to check mac address from table in gateway
    try:
        query = "select * from mac_list where mac_address = '%s'" % mac_address
        cur.execute(query)
        db.commit()
        logging.debug(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + ': (currowcount)'+ str(cur.rowcount)  + '\n')
        if cur.rowcount > 0:
            # check account_id
            for row in cur.fetchall():
                active = row[5]
            logging.debug(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + ': (row[5])'+ str(active)  + '\n')

            if active == 0: # after checking with auth server, and confirm
                #found_mac = authenticate_mac_with_auth_server(mac_address)
                logging.debug(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + ': (111111)'  + '\n')
                #return found_mac
            else:
                logging.debug(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + ': (222222)'  + '\n')
                # login success and pass (retrieve username from auth server)
                #return 1
            return 1
        else:
            logging.debug(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '*******s\n')
            # insert mac
            insert_mac_query = "INSERT INTO mac_list (mac_address, account_id, last_internet_access, active) \
                                VALUES('%s', %d, '%s', %d)" % (mac_address, -1, '0000-00-00 00:00:00', 0)
            insert_ip_query = "INSERT INTO iptables (ip_address,mac_address, account_id, bytes, start_date_time,\
                               end_date_time,internet_package) VALUES('%s', '%s', %d, %d, '%s', '%s',%d)" % \
                               (ip_address,mac_address, -1, 5000000000, str(datetime.now().strftime('%Y-%m-%d %H:%M:%S')), '0000-00-00 00:00:00', 1)
            cur.execute(insert_mac_query)
            cur.execute(insert_ip_query)
            db.commit()
            logging.debug(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + 'ip: ' + ip_address + '\n')
            insert_ip_into_sys_iptables(ip_address)
            return 0
    except:
        pass


def insert_ip_into_sys_iptables(ip):
    ipt_rule_src = 'sudo /sbin/iptables -I FORWARD -s ' + ip  + ' -j ACCEPT'
    ipt_rule_dsc = 'sudo /sbin/iptables -I FORWARD -d ' + ip  + ' -j ACCEPT'
    a = subprocess.Popen(ipt_rule_src, shell=True, stdout=subprocess.PIPE)
    b = subprocess.Popen(ipt_rule_dsc, shell=True, stdout=subprocess.PIPE)


def authenticate_mac_with_auth_server(mac_address):
    sending_mac_address = '%27' + mac_address + '%27'
    response = requests.get("https://gateway-parksiwan.c9users.io/service_mac_list.php?mac=" + sending_mac_address)
    json_data = json.loads(response.text)
    logging.debug(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '*******s' + response.text + '\n')
    # {u'macs': [{u'account_id': 1, u'mac_address': u'08:00:27:b3:68:ff'}]}
    if json_data['macs'] != None:
        for x in json_data['macs']:
            logging.debug(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '&&&&&&&'  + '\n')
            if x['account_id'] != 0 and str(x['mac_address']) == mac_address:
                logging.debug(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '++++++'  + '\n')
                return 1
    return 0


def get_mac_address(ip):
    cmd = subprocess.Popen("sudo /usr/sbin/dhcp-lease-list", shell=True, stdout=subprocess.PIPE)
    while True:
        line = cmd.stdout.readline()
        if line != '':
            results = line.split()
            if (is_valid_macaddress(results[0]) is True) and (results[1] == ip):
                return results[0]
        else:
            break
    return ''

def is_valid_macaddress(value):
    mac_pattern = re.compile(r'[a-fA-F0-9]{2}[:][a-fA-F0-9]{2}[:][a-fA-F0-9]{2}[:][a-fA-F0-9]{2}[:][a-fA-F0-9]{2}[:][a-fA-F0-9]{2}')
    is_matched = mac_pattern.match(value)
    if is_matched is None:
        return False
    else:
        return True

if __name__ == '__main__':
    #daemonize(stdout='/tmp/stdout.log', stderr='/tmp/stderr.log')
    logging.basicConfig(filename='/var/spool/squid/squid-redirect.log', level=logging.DEBUG)
    redirect_url()

