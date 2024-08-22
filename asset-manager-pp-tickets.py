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

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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

# Logging configuration
LOG_FILE = 'asset_manager_listener.log'
LOG_LEVEL = logging.DEBUG
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_SIZE = 5 * 1024 * 1024  # 5 MB
LOG_BACKUP_COUNT = 3

# Set up logging with rotation
logger = logging.getLogger('AssetManagerListener')
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
    pattern3 = r'Device (?P<ipAddress>[\d\.\/]+) removed\.'
    pattern4 = r'Device (?P<ipAddress>[\d\.\/]+) created\.'

    match3 = re.search(pattern3, message)
    match4 = re.search(pattern4, message)

    if match3:
        return match3.groupdict(), 3
    elif match4:
        return match4.groupdict(), 4
    else:
        return None, None

def handle_message(data):
    """
    Handle the received syslog message and take appropriate action.
    """
    message = data.decode("utf-8")

    parsed_data, pattern_type = parse_syslog_message(message)
    if parsed_data:
        if pattern_type == 3:
            create_decom_ticket(parsed_data['ipAddress'])
        elif pattern_type == 4:
            create_discovered_ticket(parsed_data['ipAddress'])

def create_socket(port):
    """
    Create a socket to listen for syslog messages on the specified port.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    return sock

def listen_for_syslog():
    """
    Listen for syslog messages on port 5432 and handle them.
    """
    sock = create_socket(5432)
    logger.info("Listening for Asset Manager syslog messages on UDP/5432...")

    while True:
        data, addr = sock.recvfrom(4096)  # buffer size is 4096 bytes
        handle_message(data)

if __name__ == "__main__":
    listen_for_syslog()
