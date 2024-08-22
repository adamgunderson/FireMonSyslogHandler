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

# Slack Workflow Webhooks
SLACK_WEBHOOK_URL1 = "https://hooks.slack.com/triggers/ABCDEFG/1234567890/ce6c17000ed6212db61d20c867f22c07"  # Webhook for Changes Detected
SLACK_WEBHOOK_URL2 = "https://hooks.slack.com/triggers/ABCDEFG/1234567890/5111d480a8d53dca6000b8e0eaa0d8bd"  # Webhook for Control Results

# Logging configuration
LOG_FILE = 'security_manager_listener.log'
LOG_LEVEL = logging.DEBUG
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_SIZE = 5 * 1024 * 1024  # 5 MB
LOG_BACKUP_COUNT = 3

# Set up logging with rotation
logger = logging.getLogger('SecurityManagerListener')
logger.setLevel(LOG_LEVEL)
handler = RotatingFileHandler(LOG_FILE, maxBytes=LOG_SIZE, backupCount=LOG_BACKUP_COUNT)
formatter = logging.Formatter(LOG_FORMAT)
handler.setFormatter(formatter)
logger.addHandler(handler)

def parse_syslog_message(message):
    """
    Parse the syslog message and return the parsed data and the pattern type.
    """
    pattern1 = r'\[FireMon\] (?P<deviceName>[\w\.-]+) - (?P<changeDetected>\d+) Changes Detected in Revision (?P<revision>\d+) - (?P<changeUser>\w+) - (?P<timeStamp>[\d\-T:\.]+)'
    pattern2 = r'\[FireMon\] (?P<deviceName>[\w\.-]+) - (?P<assessmentResult>FAIL|PASS) - (?P<assessmentName>.+?) - (?P<failedControls>\d+) Controls Failed out of (?P<totalControls>\d+) Total Controls - Assessment SCI (?P<assessmentSCI>[\d\.]+) - (?P<timeStamp>[\d\-T:\.]+)'

    match1 = re.search(pattern1, message)
    match2 = re.search(pattern2, message)

    if match1:
        return match1.groupdict(), 1
    elif match2:
        return match2.groupdict(), 2
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

def handle_message(data):
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

def create_socket(port):
    """
    Create a socket to listen for syslog messages on the specified port.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    return sock

def listen_for_syslog():
    """
    Listen for syslog messages on port 514 and handle them.
    """
    sock = create_socket(514)
    logger.info("Listening for Security Manager syslog messages on UDP/514...")

    while True:
        data, addr = sock.recvfrom(4096)  # buffer size is 4096 bytes
        handle_message(data)

if __name__ == "__main__":
    listen_for_syslog()
