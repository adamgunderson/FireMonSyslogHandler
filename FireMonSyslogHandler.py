import socket
import re
import json
import requests
import sys
import selectors
import urllib3
import argparse
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Slack Workflow Webhooks
SLACK_WEBHOOK_URL1 = "https://hooks.slack.com/triggers/ABCDEFG/1234567890/ce6c17000ed6212db61d20c867f22c07"  # Webhook for Changes Detected
SLACK_WEBHOOK_URL2 = "https://hooks.slack.com/triggers/ABCDEFG/1234567890/5111d480a8d53dca6000b8e0eaa0d8bd"  # Webhook for Control Results

# FireMon Configuration
FIREMON_BASE_URL = 'https://demo01.firemon.xyz'
FIREMON_USERNAME = 'firemon'
FIREMON_PASSWORD = 'firemon'
DECOMISSION_WORKFLOW = 3
DISCOVERED_DEVICE_WORKFLOW = 5

# IPs to clone access for Discovered Device.
CLONE_IPS_DEVICE_GROUPS = [
    {"sourceIp": "4.3.2.1", "deviceGroupId": 5},
    {"sourceIp": "10.0.20.20", "deviceGroupId": 5}
]

# Relay Syslog to third-Party
RELAY_HOST = 'graylog.firemon.xyz'
RELAY_PORT = 5432

# Logging configuration
LOG_FILE = 'syslog_listener.log'
LOG_LEVEL = logging.DEBUG
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_SIZE = 5 * 1024 * 1024  # 5 MB
LOG_BACKUP_COUNT = 3

#######################
## END CONFIGURATION ##
#######################


# Set up logging with rotation
logger = logging.getLogger('SyslogListener')
logger.setLevel(LOG_LEVEL)
handler = RotatingFileHandler(LOG_FILE, maxBytes=LOG_SIZE, backupCount=LOG_BACKUP_COUNT)
formatter = logging.Formatter(LOG_FORMAT)
handler.setFormatter(formatter)
logger.addHandler(handler)

FIREMON_API_URL = FIREMON_BASE_URL + '/policyplanner/api/'
FIREMON_LOGIN_URL = FIREMON_BASE_URL + '/securitymanager/api/authentication/login'
DECOMMISSION_URL = FIREMON_API_URL + f'domain/1/workflow/{DECOMISSION_WORKFLOW}/packet'
DISCOVERED_URL = FIREMON_API_URL + f'domain/1/workflow/{DISCOVERED_DEVICE_WORKFLOW}/packet'

def firemon_login():
    """
    Authenticate with the FireMon API and return the token.
    """
    headers = {'Content-Type': 'application/json'}
    payload = json.dumps({
        'username': FIREMON_USERNAME,
        'password': FIREMON_PASSWORD
    })

    auth_response = requests.post(FIREMON_LOGIN_URL, headers=headers, data=payload, verify=False)
    token = auth_response.json().get('token')

    if not token:
        logger.error('Failed to obtain token. Please check your credentials.')
        sys.exit(1)

    logger.info('Successfully authenticated with FireMon.')
    return token

def create_decom_ticket(ip_address):
    """
    Create a decommission ticket in FireMon for the given IP address.
    """
    token = firemon_login()
    headers = {
        'Content-Type': 'application/json',
        'X-FM-AUTH-Token': token
    }
    payload = {
        "variables": {
            "requesterName": "Asset Manager",
            "requesterEmail": "asset.manager@firemon.xyz",
            "summary": f"{ip_address} Removed",
            "priority": "Low",
            "teamName": "Decom Team",
            "businessNeed": "Decommission removed server"
        },
        "policyPlanRequirements": [
            {
                "addresses": [ip_address],
                "requirementType": "DECOM",
                "childKey": "decom_servers",
                "variables": {},
                "description": "Device Removed"
            }
        ]
    }

    response = requests.post(DECOMMISSION_URL, headers=headers, data=json.dumps(payload), verify=False)
    if response.status_code == 200:
        logger.info("Decommission ticket created successfully.")
    else:
        logger.error(f"Failed to create decommission ticket: {response.status_code}, {response.text}")

def create_discovered_ticket(ip_address):
    """
    Create a discovered device ticket in FireMon for the given IP address.
    """
    token = firemon_login()
    headers = {
        'Content-Type': 'application/json',
        'X-FM-AUTH-Token': token
    }
    payload = {
        "variables": {
            "requesterName": "Asset Manager",
            "requesterEmail": "asset.manager@firemon.xyz",
            "summary": f"Device Discovered at {ip_address}",
            "priority": "High",
            "teamName": "Network",
            "businessNeed": "New access needed."
        },
        "policyPlanRequirements": [
            {
                "addressesToClone": [ip_address],
                "requirementType": "CLONE",
                "childKey": "clone_server",
                "variables": {"deviceGroupId": clone['deviceGroupId']},
                "sourceIp": clone['sourceIp'],
                "description": f"Need access for {ip_address}"
            } for clone in CLONE_IPS_DEVICE_GROUPS
        ]
    }

    response = requests.post(DISCOVERED_URL, headers=headers, data=json.dumps(payload), verify=False)
    if response.status_code == 200:
        logger.info("Discovered ticket created successfully.")
    else:
        logger.error(f"Failed to create discovered ticket: {response.status_code}, {response.text}")

def parse_syslog_message(message):
    """
    Parse the syslog message and return the parsed data and the pattern type.
    """
    pattern1 = r'\[FireMon\] (?P<deviceName>[\w\.-]+) - (?P<changeDetected>\d+) Changes Detected in Revision (?P<revision>\d+) - (?P<changeUser>\w+) - (?P<timeStamp>[\d\-T:\.]+)'
    pattern2 = r'\[FireMon\] (?P<deviceName>[\w\.-]+) - (?P<assessmentResult>FAIL|PASS) - (?P<assessmentName>.+?) - (?P<failedControls>\d+) Controls Failed out of (?P<totalControls>\d+) Total Controls - Assessment SCI (?P<assessmentSCI>[\d\.]+) - (?P<timeStamp>[\d\-T:\.]+)'
    pattern3 = r'Device (?P<ipAddress>[\d\.\/]+) removed\.'
    pattern4 = r'Device (?P<ipAddress>[\d\.\/]+) created\.'

    match1 = re.search(pattern1, message)
    match2 = re.search(pattern2, message)
    match3 = re.search(pattern3, message)
    match4 = re.search(pattern4, message)

    if match1:
        return match1.groupdict(), 1
    elif match2:
        return match2.groupdict(), 2
    elif match3:
        return match3.groupdict(), 3
    elif match4:
        return match4.groupdict(), 4
    else:
        return None, None

def post_to_slack(data, webhook_url):
    """
    Post the parsed data to the specified Slack webhook URL.
    """
    payload = json.dumps(data)
    response = requests.post(webhook_url, data=payload, headers={'Content-Type': 'application/json'})
    if response.status_code == 200:
        logger.info("Message posted to Slack")
    else:
        logger.error(f"Failed to post message to Slack: {response.status_code}, {response.text}")

def handle_message(data, sock, relay=False, relay_output=False):
    """
    Handle the received syslog message and take appropriate action.
    """
    message = data.decode("utf-8")

    parsed_data, pattern_type = parse_syslog_message(message)
    if parsed_data:
        if pattern_type == 1:
            parsed_data['timeStamp'] = parsed_data['timeStamp'].split('.')[0]
            post_to_slack(parsed_data, SLACK_WEBHOOK_URL1)
        elif pattern_type == 2:
            parsed_data['timeStamp'] = parsed_data['timeStamp'].split('.')[0]
            post_to_slack(parsed_data, SLACK_WEBHOOK_URL2)
        elif pattern_type == 3:
            create_decom_ticket(parsed_data['ipAddress'])
        elif pattern_type == 4:
            create_discovered_ticket(parsed_data['ipAddress'])

    if relay:
        sock.sendto(data, (RELAY_HOST, RELAY_PORT))
        if relay_output:
            logger.info(f"Relayed message to {RELAY_HOST}:{RELAY_PORT}")

def create_socket(port):
    """
    Create a socket to listen for syslog messages on the specified port.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    return sock

def listen_for_syslog(relay_output):
    """
    Listen for syslog messages on multiple ports and handle them.
    """
    sel = selectors.DefaultSelector()
    sock1 = create_socket(514)
    sock2 = create_socket(5432)
    sel.register(sock1, selectors.EVENT_READ, data={'port': 514})
    sel.register(sock2, selectors.EVENT_READ, data={'port': 5432})

    logger.info("Listening for syslog messages on UDP/514 and UDP/5432...")

    while True:
        events = sel.select()
        for key, _ in events:
            sock = key.fileobj
            data, addr = sock.recvfrom(4096)  # buffer size is 4096 bytes
            relay = (key.data['port'] == 5432)
            handle_message(data, sock, relay, relay_output)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Syslog Listener")
    parser.add_argument("--relay-output", action="store_true", help="Output a message every time a syslog message is relayed on port 5432")
    args = parser.parse_args()
    listen_for_syslog(args.relay_output)
