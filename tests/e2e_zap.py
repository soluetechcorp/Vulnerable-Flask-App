import requests
from zapv2 import ZAPv2 as ZAP
import time
import datetime
from os import getcwd
import logging

# Test Automation Part of the Script

target_url = 'http://localhost:5050'
# Do not route sensitive test traffic through a local HTTP proxy by default.
# Security: Avoid sending auth tokens and PII to third-party proxies/logs (CWE-532).
proxies = {}

auth_dict = {'username': 'admin', 'password': 'admin123'}

# Perform login with TLS certificate validation enabled to prevent MITM attacks (CWE-295).
login = requests.post(target_url + '/login',
                      proxies=proxies, json=auth_dict, verify=True)  # Security: verify=True enables certificate validation


if login.status_code == 200:  # if login is successful
    # Safely extract Authorization header. Use .get to avoid KeyError.
    auth_token = login.headers.get('Authorization')
    auth_header = {"Authorization": auth_token} if auth_token else {}

    # now lets run some operations
    # GET Customer by ID

    # Perform sensitive authenticated requests without routing them through an external proxy
    # and with TLS certificate verification enabled (CWE-295, CWE-532).
    get_cust_id = requests.get(
        target_url + '/get/2', headers=auth_header, verify=True)  # Security: avoid proxies and enable verification
    if get_cust_id.status_code == 200:
        # Do not print PII or full JSON responses to stdout. Redact sensitive data before logging.
        print("Get Customer by ID Response - status: {}".format(get_cust_id.status_code))
        print("Response content redacted for privacy")
        print()

    post = {'id': 2}
    fetch_customer_post = requests.post(
        target_url + '/fetch/customer', json=post, headers=auth_header, verify=True)  # Security: verify certs, no proxy
    if fetch_customer_post.status_code == 200:
        # Redact sensitive payloads before printing/logging
        print("Fetch Customer POST Response - status: {}".format(fetch_customer_post.status_code))
        print("Response content redacted for privacy")
        print()

    search = {'search': 'dleon'}
    search_customer_username = requests.post(
        target_url + '/search', json=search, headers=auth_header, verify=True)  # Security: verify certs, no proxy
    if search_customer_username.status_code == 200:
        print("Search Customer POST Response - status: {}".format(search_customer_username.status_code))
        print("Response content redacted for privacy")
        print()


# ZAP Operations

zap = ZAP(proxies={'http': 'http://localhost:8090',
                   'https': 'http://localhost:8090'})

if 'Light' not in zap.ascan.scan_policy_names:
    print("Adding scan policies")
    zap.ascan.add_scan_policy(
        "Light", alertthreshold="Medium", attackstrength="Low")

active_scan_id = zap.ascan.scan(target_url, scanpolicyname='Light')

print("active scan id: {0}".format(active_scan_id))

# now we can start monitoring the spider's status
while int(zap.ascan.status(active_scan_id)) < 100:
    print("Current Status of ZAP Active Scan: {0}%".format(
        zap.ascan.status(active_scan_id)))
    time.sleep(10)

now = datetime.datetime.now().strftime("%m/%d/%Y")
alert_severity = 't;t;t;t'  # High;Medium;Low;Info
# CWEID;#WASCID;Description;Other Info;Solution;Reference;Request Header;Response Header;Request Body;Response Body
alert_details = 't;t;t;t;t;t;f;f;f;f'
source_info = 'Vulnerability Report for Flask_API;Abhay Bhargav;API Team;{};{};v1;v1;API Scan Report'.format(
    now, now)
path = getcwd() + "/zap-report.json"
zap.exportreport.generate(path, "json", sourcedetails=source_info,
                          alertseverity=alert_severity, alertdetails=alert_details, scanid=active_scan_id)

zap.core.shutdown()
