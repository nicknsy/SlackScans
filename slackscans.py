import logging
import time
import os
import urllib

from securitycenter import SecurityCenter5
from ConfigParser import ConfigParser
from slackclient import SlackClient

# Function to check available file names
def checkfile(name, extension):
    occurrence = 0
    available = name + extension

    while os.path.exists(available):
        occurrence += 1
        available = name + '-' + occurrence.__str__() + extension

    return available

# Function to post results to Slack channel
def postresults(scans):
    for scan in scans:
        scan_name = scan['name']
        scan_id = scan['id']
        scan_link = '%s://%s/#vulnerabilities/scanResult/%s/' % (center_protocol, center_ip, scan_id)
        encoded_link = '{"scanName":"%s","repositoryID":"%s"}' % (scan_name, scan['repository']['id'])
        slackclient.api_call(
            'chat.postMessage',
            channel=slack_channel,
            text='Scan Completed: <%s|%s> (%s)' % (scan_link + urllib.quote(encoded_link), scan_name, scan_id)
        )

# Load config file and values
config = ConfigParser()
config.read('config.cfg')

center_ip = config.get('SecurityCenter', 'ip')
center_port = config.getint('SecurityCenter', 'port')
center_protocol = config.get('SecurityCenter', 'protocol')
center_user = config.get('SecurityCenter', 'user')
center_pass = config.get('SecurityCenter', 'password')

slack_key = config.get('Slack', 'api_key')
slack_channel = config.get('Slack', 'channel')

settings_debug = config.getboolean('Settings', 'debug')
settings_interval = config.getint('Settings', 'interval')

# Setup logging
if not os.path.exists('logs'):
    os.mkdir('logs')

date = time.strftime('%Y-%m-%d_%H-%M', time.localtime(time.time()))
level = logging.DEBUG if settings_debug else logging.ERROR
filename = checkfile(os.path.join('logs', date), '.log')

logging.basicConfig(filename=filename, level=level)

# Establish connection with slack and SecurityCenter
slackclient = SlackClient(slack_key)
securitycenter = SecurityCenter5(host=center_ip, port=center_port, scheme=center_protocol)

securitycenter.login(center_user, center_pass)

# Look for new scans at interval
running_scans = []
while True:
    time.sleep(settings_interval)

    completed_scans = []
    results = securitycenter.get('scanResult?filter=usable&fields=status%2Cname%2Cstatus%2Crepository').json()

    for result in results['response']['usable']:
        if result['status'] == 'Running':
            if result['id'] not in running_scans:
                running_scans.append(result['id'])
        elif result['id'] in running_scans:
            if result['status'] == 'Completed':
                running_scans.remove(result['id'])
                completed_scans.append(result)
            else:
                running_scans.remove(result['id'])

    postresults(completed_scans)