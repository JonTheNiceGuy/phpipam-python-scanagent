#! /usr/bin/env python3
import re
import sys
import time
import pytz
import nmap3
import logging
import requests
from parse_it import ParseIt
from typing import Mapping, Optional, Union
from datetime import datetime

parser = ParseIt()

logging.basicConfig(
    level=parser.read_configuration_variable(
        'LOG_LEVEL', default_value='INFO'),
    format='%(asctime)s - %(levelname)s - %(message)s'
)
server = parser.read_configuration_variable('IPAM_SERVER')
api_client = parser.read_configuration_variable('IPAM_API_CLIENT')
api_token = parser.read_configuration_variable('IPAM_API_TOKEN')
agent_code = parser.read_configuration_variable('IPAM_API_AGENT_CODE')
sleep_duration = parser.read_configuration_variable(
    'IPAM_SLEEP_DURATION', default_value='5m')
min_time_between_scans = parser.read_configuration_variable(
    'IPAM_MIN_TIME_BETWEEN_SCANS', default_value='1h')
always_update_seen_hosts = parser.read_configuration_variable(
    'IPAM_ALWAYS_UPDATE', default_value='1')
remove_old_hosts = parser.read_configuration_variable(
    'IPAM_REMOVE_OLD_HOSTS', default_value='1')
remove_old_host_delay = parser.read_configuration_variable(
    'IPAM_REMOVE_OLD_HOST_DELAY', default_value='48h')

logging.info(f"Version: 1.0.0 Author: Jon Spriggs jon@sprig.gs")

if server is None or api_client is None or api_token is None or agent_code is None:
    logging.error(f"Missing required values. Halting.")
    exit(1)

logging.info(f"Server: {server}, api_client: {api_client}, api_token: {api_token}, agent_code: {agent_code}, sleep_duration: {sleep_duration}, always_update_seen_hosts: {always_update_seen_hosts}")

def time_match(duration):
    duration_pattern = r'^(([.\d]+)([smh]|))(([.\d]+)([smh])|)(([.\d]+)([smh])|)$'
    re_match = re.match(duration_pattern, duration)
    duration_seconds = 0

    if re_match:
        if re_match.group(3) == 's':
            duration_seconds += float(re_match.group(2))
        if re_match.group(6) == 's':
            duration_seconds += float(re_match.group(5))
        if re_match.group(9) == 's':
            duration_seconds += float(re_match.group(8))
        if re_match.group(3) == 'm':
            duration_seconds += (float(re_match.group(2)) * 60)
        if re_match.group(6) == 'm':
            duration_seconds += (float(re_match.group(5)) * 60)
        if re_match.group(9) == 'm':
            duration_seconds += (float(re_match.group(8)) * 60)
        if re_match.group(3) == 'h':
            duration_seconds += (float(re_match.group(2)) * 60 * 60)
        if re_match.group(6) == 'h':
            duration_seconds += (float(re_match.group(5)) * 60 * 60)
        if re_match.group(9) == 'h':
            duration_seconds += (float(re_match.group(8)) * 60 * 60)
        if re_match.group(3) == 'h' and re_match.group(6) is not None and len(re_match.group(6)) == 0:
            duration_seconds += (float(re_match.group(5)) * 60)
        if re_match.group(3) == 'm' and re_match.group(6) is not None and len(re_match.group(6)) == 0:
            duration_seconds += float(re_match.group(5))
        if re_match.group(6) == 'h' and re_match.group(9) is not None and len(re_match.group(9)) == 0:
            duration_seconds += (float(re_match.group(8)) * 60)
        if re_match.group(6) == 'm' and re_match.group(9) is not None and len(re_match.group(9)) == 0:
            duration_seconds += float(re_match.group(8))
        return duration_seconds
    else:
        raise ValueError(
            f"Invalid format for duration (got {duration}")

sleep_seconds = time_match(sleep_duration)
logging.info(f"Sleep Duration {sleep_duration} = {sleep_seconds} seconds")

time_between_scans_seconds = time_match(min_time_between_scans)
logging.info(
    f"Time between scans {min_time_between_scans} = {time_between_scans_seconds} seconds = {time_between_scans_seconds / 60} minutes")

if remove_old_hosts == '1':
    remove_old_host_delay_seconds = time_match(remove_old_host_delay)
    logging.info(
        f"Remove old host delay {remove_old_host_delay} = {remove_old_host_delay_seconds} seconds = {remove_old_host_delay_seconds / 60} minutes = {remove_old_host_delay_seconds / 60 / 60} hours")

def getFromPhpIpam(
    server: str,
    api_client: str,
    api_token: str,
    endpoint: str,
    data: Optional[
        Union[
            Mapping[str, str],
            None
        ]
    ] = None,
    secure=True
):
    headers = {
        'token': api_token,
        'Content-Type': 'application/json'
    }
    if data is None:
        pass
    else:
        headers.update(data)

    response = requests.get(
        f"https://{server}/api/{api_client}/{endpoint}", headers=headers, verify=secure)
    return_data = response.json()
    if 'data' in return_data:
        logging.debug(
            f"GET {endpoint} requested; (len: {len(return_data['data'])})")
        return return_data['data']

def deletePhpIpam(
    server: str,
    api_client: str,
    api_token: str,
    endpoint: str,
    id: int,
    data: Mapping[str, str],
    secure=True
):
    headers = {
        'token': api_token,
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    response = requests.delete(
        f"https://{server}/api/{api_client}/{endpoint}/{id}/", headers=headers, data=data, verify=secure)
    try:
        logging.debug(
            f"DELETE {endpoint}/{id} requested with {data}; {response.json()}")
    except any:
        logging.error(f"Error in DELETE {endpoint}/{id} / {data}")
    return response.json()

def updatePhpIpam(
    server: str,
    api_client: str,
    api_token: str,
    endpoint: str,
    id: int,
    data: Mapping[str, str],
    secure=True
):
    headers = {
        'token': api_token,
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    response = requests.patch(
        f"https://{server}/api/{api_client}/{endpoint}/{id}/", headers=headers, data=data, verify=secure)
    try:
        logging.debug(
            f"PATCH {endpoint}/{id} requested with {data}; {response.json()}")
    except any:
        logging.error(f"Error in PATCH {endpoint}/{id} / {data}")
    return response.json()

def createPhpIpam(
    server: str,
    api_client: str,
    api_token: str,
    endpoint: str,
    data: Mapping[str, str],
    secure=True
):
    headers = {
        'token': api_token,
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    response = requests.post(
        f"https://{server}/api/{api_client}/{endpoint}/", headers=headers, data=data, verify=secure)
    try:
        logging.debug(
            f"POST {endpoint} requested with {data}; {response.json()}")
    except any:
        logging.error(f"Error in POST {endpoint} / {data}")
    return response.json()

def nowTime():
    try:
        return str(datetime.now(pytz.UTC).strftime('%Y-%m-%d %H:%M:%S'))
    except:
        return "0000-00-00 00:00:00"

while True:
    scanagents = getFromPhpIpam(
        server, api_client, api_token, 'tools/scanagents')
    scanagentId = 0
    for scanagent in scanagents:
        if scanagent['code'] == agent_code and scanagent['id'] is not None:
            scanagentId = int(scanagent['id'])
            break

    if scanagentId > 0:
        logging.info(f"Scan agent detected: {agent_code}.\n")
        logging.info(f"Starting run {nowTime()}.\n")

        tags = getFromPhpIpam(server, api_client, api_token, 'tools/tags')
        subnets = getFromPhpIpam(server, api_client, api_token, 'subnets')

        online_tag = 2
        offline_tag = 1
        for tag in tags:
            if tag['type'] == 'Used':
                online_tag = tag['id']
            elif tag['type'] == 'Offline':
                offline_tag = tag['id']

        for subnet in subnets:
            cidr = f"{subnet['subnet']}/{subnet['mask']}"
            str_scanAgent = str(subnet['scanAgent'])
            str_scanagentId = str(scanagentId)
            str_pingSubnet = str(subnet['pingSubnet'])
            str_resolveDNS = str(subnet['resolveDNS'])
            now_timestamp = datetime.now(pytz.UTC).timestamp()
            scan_gap = time_between_scans_seconds
            now_less_scan_gap = now_timestamp - scan_gap
            last_acceptable_scan = datetime.fromtimestamp(now_less_scan_gap)
            logging.debug(
                f"Now: {now_timestamp}; Last acceptable scan: {last_acceptable_scan} [{now_less_scan_gap}]")
            last_timestamp = 0
            timeLastScan = datetime.fromtimestamp(0)
            if subnet['lastScan'] is not None:
                timeLastScan = datetime.strptime(
                    subnet['lastScan'], '%Y-%m-%d %H:%M:%S')
                last_timestamp = timeLastScan.timestamp()
            scan_now = now_less_scan_gap > last_timestamp
            logging.info(
                f"Checking Subnet {subnet['id']} : {cidr} '{subnet['description']}'")
            logging.debug(
                f"  str_scanAgent({str_scanAgent}) == str_scanagentId({str_scanagentId}) ? {str_scanAgent == str_scanagentId}")
            logging.debug(
                f"  str_pingSubnet({str_pingSubnet}) == '1' ? {str_pingSubnet == str('1')}")
            logging.debug(
                f"  now_less_scan_gap({now_less_scan_gap}) [{last_acceptable_scan}] > last_timestamp({last_timestamp}) [{subnet['lastScan']}] == {scan_now}")
            if str_scanAgent == str_scanagentId and str_pingSubnet == str('1') and scan_now:
                nameservers = ' -n'
                if str_resolveDNS == str('1'):
                    nameservers = ''
                    if 'nameservers' in subnet:
                        nameservers = f" --dns-servers {subnet['nameservers']['namesrv1'].replace(';', ',')}"

                print(f"Scanning subnet {cidr} '{subnet['description']}'.")
                add_online = 0
                update_online = 0
                update_offline = 0
                update_removed = 0
                addresses = getFromPhpIpam(
                    server, api_client, api_token, f"subnets/{subnet['id']}/addresses")

                addresses_list = {}
                excluded_list = []
                if addresses is not None and len(addresses) > 0:
                    for address in addresses:
                        addresses_list.update({address['ip']: address})
                        if address['excludePing'] == '1':
                            excluded_list.append(address['ip'])

                exclude = ''
                if len(excluded_list) > 0:
                    exclude = f" --exclude {','.join(excluded_list)}"
                logging.debug("Scan Start")
                nmap = nmap3.NmapScanTechniques()
                hosts_list = nmap.nmap_ping_scan(
                    cidr, args=f"-T5{nameservers}{exclude}")
                nmap_stats = {
                    'runtime': hosts_list['runtime'], 'stats': hosts_list['stats'], 'task_results': hosts_list['task_results']}

                logging.debug(f"Scan Stop: {nmap_stats}")

                hosts_list.pop('runtime')
                hosts_list.pop('stats')
                hosts_list.pop('task_results')

                if hosts_list is not None and len(hosts_list) > 0:
                    for ip in hosts_list:
                        status = hosts_list[ip]
                        if 'state' in status['state'] and status['state']['state'] == 'up' and status['state']['reason'] != 'reset':
                            hostname = f"ip-{ip.replace('.', '-')}"
                            if len(status['hostname']) > 0 and 'name' in status['hostname'][0]:
                                hostname = status['hostname'][0]['name']

                            ip_found = False
                            id = ''
                            for key in addresses_list:
                                if key == ip:
                                    ip_found = True
                                    address_id = addresses_list[key]['id']
                                    break

                            if ip_found:  # Update
                                if always_update_seen_hosts == '1' or addresses_list[ip]['tag'] != online_tag:
                                    thisTime = str(nowTime())
                                    data = {
                                        'hostname': hostname,
                                        'tag': f"{online_tag}",
                                        'lastSeen': thisTime
                                    }
                                    print(updatePhpIpam(
                                        server, api_client, api_token, 'addresses', address_id, data))
                                    update_online += 1

                            elif subnet['discoverSubnet'] == '1':
                                thisTime = str(nowTime())
                                data = {
                                    'subnetId': subnet['id'],
                                    'ip': ip,
                                    'hostname': hostname,
                                    'tag': f"{online_tag}",
                                    'lastSeen': thisTime
                                }
                                print(createPhpIpam(server, api_client,
                                      api_token, 'addresses', data))
                                add_online += 1

                    if addresses_list is not None and len(addresses_list) > 0:
                        for ip in addresses_list:
                            status = addresses_list[ip]
                            now_timestamp = datetime.now(pytz.UTC).timestamp()
                            acceptable_down_gap = now_timestamp - remove_old_host_delay_seconds
                            last_seen = datetime.strptime(
                                status['lastSeen'], '%Y-%m-%d %H:%M:%S').timestamp()
                            if (remove_old_hosts == '1' and
                                status['tag'] == offline_tag and
                                acceptable_down_gap < last_seen and
                                (
                                    'state' in hosts_list[ip] and
                                    'state' in hosts_list[ip]['state'] and
                                    hosts_list[ip]['state']['state'] == 'down'
                            ) or (
                                    'state' in hosts_list[ip] and
                                    'state' in hosts_list[ip]['state'] and
                                    hosts_list[ip]['state']['state'] == 'up' and
                                    hosts_list[ip]['state']['reason'] == 'reset'
                            )
                            ):
                                print(deletePhpIpam(server, api_client,
                                      api_token, 'addresses', status['id'], {}))
                                update_removed += 1
                            elif status['excludePing'] or status['tag'] == offline_tag:
                                pass
                            elif ip not in hosts_list or (
                                'state' in hosts_list[ip] and
                                'state' in hosts_list[ip]['state'] and
                                hosts_list[ip]['state']['state'] == 'down'
                            ) or (
                                'state' in hosts_list[ip] and
                                'state' in hosts_list[ip]['state'] and
                                hosts_list[ip]['state']['state'] == 'up' and
                                hosts_list[ip]['state']['reason'] == 'reset'
                            ):  # Offline
                                data = {'tag': f"{offline_tag}"}
                                print(updatePhpIpam(server, api_client,
                                      api_token, 'addresses', status['id'], data))
                                update_offline += 1

                thisTime = str(nowTime())
                if update_online + add_online + update_offline + update_removed > 0:
                    print(
                        f"Added: {add_online}, Changed: {update_online} online {update_offline} offline {update_removed} purged at {thisTime}")
                else:
                    print(f"No changes at {thisTime}")
                if subnet['discoverSubnet'] == '1':
                    data = {'lastScan': thisTime, 'lastDiscovery': thisTime}
                else:
                    data = {'lastScan': thisTime}
                updatePhpIpam(server, api_client, api_token,
                              'subnets', subnet['id'], data)
                updatePhpIpam(server, api_client, api_token,
                              'tools/scanagents', scanagent['id'], {'last_access': thisTime})
    time.sleep(sleep_seconds)
