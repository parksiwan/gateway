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


def redirect_url():
    db = MySQLdb.connect(host="127.0.0.1", user="root", passwd="psw1101714", db="gateway")
    cur = db.cursor()
    
    request = sys.stdin.readline()
    found_mac = 0;
    while True:
        logging.debug(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '(req)'+ request  + '\n')
        [ch_id, url, ipaddr, method, user] = request.split()
        mac = get_mac_address(ipaddr)
        if mac != ' ':
            # ---> authenticate mac with local db
            found_mac  = authenticate_mac_with_local_db(db, cur, mac)
            # ---> authenticate mac with remote auth server
            #found_mac  = authenticate_mac_with_auth_server(mac)
            # ---> authenticate mac with local db
            # The following is to check mac address from table in gateway
            #try:
            #    query = "select * from mac_list where mac_address = '%s'" % mac
            #    cur.execute(query)
            #    db.commit()
            #    if cur.rowcount > 0:
            #        found_mac = 1
            #    else:
            #        found_mac = 0
            #except:
            #    pass
        logging.debug(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '(found_mac)'+ str(found_mac)  + '\n')

        response  = ch_id + ' OK'
        if (found_mac == 1):    # Later, for this mac set qos profile to normal otherwise shaping
            response += ' status=200 url='
            response += url
            response += '\n'
            sys.stdout.write(response)
            sys.stdout.flush()
            continue

        if 'mywifi' in url:    # takes user to login page for registration or login
            response += ' status=302 url=https://gateway-parksiwan.c9users.io/login.php?mac='
            response += mac
            response += '\n'
            sys.stdout.write(response)
            sys.stdout.flush()
            continue

        #response += ' status=200 url='
        response += ' status=302 url=https://gateway-parksiwan.c9users.io/login.php?mac='
        response += mac
        response += '\n'
        sys.stdout.write(response)
        sys.stdout.flush()
        logging.debug(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + ': (res)' + response + '\n')
        request = sys.stdin.readline()
    db.close()
    cur.close()
    
def authenticate_mac_with_local_db(db, cur, mac_address):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    # ---> authenticate mac with local db
    # The following is to check mac address from table in gateway
    try:
        query = "select * from mac_list where mac_address = '%s'" % mac_address
        cur.execute(query)
        db.commit()
        if cur.rowcount > 0:
            # check account_id
            for row in cur.fetchone():
                active = row[4]
            if active == 0: # after checking with auth server, and confirm
                found_mac = authenticate_mac_with_auth_server(mac_address)
                return found_mac
            else:
                # login success and pass (retrieve username from auth server)
                return 1
        else:
            logging.debug(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '*******s\n')
            # insert mac
            insert_query = "INSERT INTO mac_list (mac_address, account_id, last_internet_access, active) \
                            VALUES('%s', %d, '%s', %d)" % (mac_address, -1, '0000-00-00 00:00:00', 0)
            cur.execute(insert_query)
            db.commit()
            return 0
    except:
        pass

def authenticate_mac_with_auth_server(mac_address):
    sending_mac_address = '%27' + mac_address + '%27'
    response = requests.get("https://gateway-parksiwan.c9users.io/service_mac_list.php?mac=" + sending_mac_address)
    json_data = json.loads(response.text)
    # {u'macs': [{u'account_id': 1, u'mac_address': u'08:00:27:b3:68:ff'}]}
    if json_data['macs'] != None:
        for x in json_data['macs']:
            if x['mac_address'] == mac_address:
                return 1
    return 0


def get_mac_address(ip):
    cmd = subprocess.Popen("/usr/sbin/dhcp-lease-list", shell=True, stdout=subprocess.PIPE)
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
    logging.basicConfig(filename='/var/spool/squid/squid-redirect.log', level=logging.DEBUG)
    redirect_url()

