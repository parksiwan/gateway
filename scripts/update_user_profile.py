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

import json
import requests
import logging
from datetime import datetime
from daemonize import daemonize


def authenticate_mac_with_auth_server(mac_address):
    sending_mac_address = '%27' + mac_address + '%27'
    response = requests.get("https://gateway-parksiwan.c9users.io/service_mac_list.php?mac=" + sending_mac_address)
    json_data = json.loads(response.text)
    logging.debug(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '*******s' + response.text + '\n')
    # {u'macs': [{u'account_id': 1, u'mac_address': u'08:00:27:b3:68:ff'}]}
    # str(json_data['macs'][x]).strip('\'') == mac_address
    if json_data['macs'] != None:
        for key in json_data['macs']:
            if key == 'account_id' and json_data['macs'][key] > 0:
               return 1
    return 0


if __name__ == '__main__':
    daemonize(stdout='/tmp/stdout.log', stderr='/tmp/stderr.log')
    authenticate_mac_with_auth_server('08:00:27:b3:68:fb')
