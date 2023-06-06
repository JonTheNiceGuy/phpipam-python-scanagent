import re
import sys
import time
import nmap3
import requests
from parse_it import ParseIt
from typing import Mapping, Optional, Union
from datetime import datetime

parser = ParseIt()

server = parser.read_configuration_variable('IPAM_SERVER')
api_client = parser.read_configuration_variable('IPAM_API_CLIENT')
api_token = parser.read_configuration_variable('IPAM_API_TOKEN')
agent_code = parser.read_configuration_variable('IPAM_API_AGENT_CODE')
sleep_duration = parser.read_configuration_variable('IPAM_SLEEP_DURATION', default_value='5m')
always_update_seen_hosts = parser.read_configuration_variable('IPAM_ALWAYS_UPDATE', default_value='1')

print(f"Server: {server}, api_client: {api_client}, api_token: {api_token}, agent_code: {agent_code}, sleep_duration: {sleep_duration}, always_update_seen_hosts: {always_update_seen_hosts}")

sleep_pattern = r'^(([.\d]+)([smh]|))(([.\d]+)([smh])|)(([.\d]+)([smh])|)$'

sleep_match = re.match(sleep_pattern, sleep_duration)
sleep_seconds = 0

if sleep_match:
    if sleep_match.group(3) == 's':
        sleep_seconds += float(sleep_match.group(2))
    if sleep_match.group(6) == 's':
        sleep_seconds += float(sleep_match.group(5))
    if sleep_match.group(9) == 's':
        sleep_seconds += float(sleep_match.group(8))
    if sleep_match.group(3) == 'm':
        sleep_seconds += (float(sleep_match.group(2)) * 60)
    if sleep_match.group(6) == 'm':
        sleep_seconds += (float(sleep_match.group(5)) * 60)
    if sleep_match.group(9) == 'm':
        sleep_seconds += (float(sleep_match.group(8)) * 60)
    if sleep_match.group(3) == 'h':
        sleep_seconds += (float(sleep_match.group(2)) * 60 * 60)
    if sleep_match.group(6) == 'h':
        sleep_seconds += (float(sleep_match.group(5)) * 60 * 60)
    if sleep_match.group(9) == 'h':
        sleep_seconds += (float(sleep_match.group(8)) * 60 * 60)
    if sleep_match.group(3) == 'h' and sleep_match.group(6) is not None and len(sleep_match.group(6)) == 0:
        sleep_seconds += (float(sleep_match.group(5)) * 60)
    if sleep_match.group(3) == 'm' and sleep_match.group(6) is not None and len(sleep_match.group(6)) == 0:
        sleep_seconds += float(sleep_match.group(5))
    if sleep_match.group(6) == 'h' and sleep_match.group(9) is not None and len(sleep_match.group(9)) == 0:
        sleep_seconds += (float(sleep_match.group(8)) * 60)
    if sleep_match.group(6) == 'm' and sleep_match.group(9) is not None and len(sleep_match.group(9)) == 0:
        sleep_seconds += float(sleep_match.group(8))
else:
    raise ValueError(f"Invalid format for sleep duration (got {sleep_duration}")

print(f"Sleep Duration {sleep_duration} = {sleep_seconds} seconds")

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
        secure = True
    ):
    headers = {
        'token': api_token,
        'Content-Type': 'application/json'
    }
    if data is None:
        pass
    else:
        headers.update(data)

    response = requests.get(f"https://{server}/api/{api_client}/{endpoint}", headers=headers, verify=secure)
    return_data = response.json()
    if 'data' in return_data:
        return return_data['data']

def updatePhpIpam(
        server: str,
        api_client: str,
        api_token: str,
        endpoint: str,
        id: int,
        data: Mapping[str, str],
        secure = True
    ):
    headers = {
        'token': api_token,
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    response = requests.patch(f"https://{server}/api/{api_client}/{endpoint}/{id}/", headers=headers, data=data, verify=secure)
    return response.json()

def createPhpIpam(
        server: str,
        api_client: str,
        api_token: str,
        endpoint: str,
        data: Mapping[str, str],
        secure = True
    ):
    headers = {
        'token': api_token,
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    response = requests.post(f"https://{server}/api/{api_client}/{endpoint}/", headers=headers, data=data, verify=secure)
    return response.json()

def now():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

while True:
    scanagents = getFromPhpIpam(server, api_client, api_token, 'tools/scanagents')
    scanagentId = 0
    for scanagent in scanagents:
        if scanagent['code'] == agent_code and scanagent['id'] is not None:
            scanagentId = int(scanagent['id'])
            break

    if scanagentId > 0:
        sys.stderr.write(f"Scan agent detected: {agent_code}.\n")

        sys.stderr.write(f"Starting run {now()}.\n")

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
            if subnet['scanAgent'] == scanagentId and subnet['pingSubnet'] == '1':
                nameservers = ' -n'
                if subnet['resolveDNS'] == '1':
                    nameservers = ''
                    if 'nameservers' in subnet:
                        nameservers = f" --dns-servers {subnet['nameservers']['namesrv1'].replace(';', ',')}"

                cidr = f"{subnet['subnet']}/{subnet['mask']}"
                print(f"Scanning subnet {cidr} '{subnet['description']}'.")
                add_online=0
                update_online=0
                update_offline=0
                addresses = getFromPhpIpam(server, api_client, api_token, f"subnets/{subnet['id']}/addresses")

                addresses_list = {}
                excluded_list = []
                if addresses is not None and len(addresses) > 0:
                    for address in addresses:
                        addresses_list.update({address['ip']: address})
                        if address['excludePing'] == '1':
                            excluded_list.append(address['ip'])

                exclude=''
                if len(excluded_list) > 0:
                    exclude=f" --exclude {','.join(excluded_list)}"

                nmap = nmap3.NmapScanTechniques()
                hosts_list = nmap.nmap_ping_scan(cidr, args=f"-T5{nameservers}{exclude}")
                nmap_stats = {'runtime': hosts_list['runtime'], 'stats': hosts_list['stats'], 'task_results': hosts_list['task_results']}
                hosts_list.pop('runtime')
                hosts_list.pop('stats')
                hosts_list.pop('task_results')

                if hosts_list is not None and len(hosts_list) > 0:
                    for ip in hosts_list:
                        status = hosts_list[ip]
                        if 'state' in status['state'] and status['state']['state'] == 'up':
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

                            if ip_found: # Update
                                if always_update_seen_hosts == '1' or addresses_list[ip]['tag'] != online_tag:
                                    data = {'hostname': hostname, 'tag': f"{online_tag}", 'lastSeen': now()}
                                    print(updatePhpIpam(server, api_client, api_token, 'addresses', address_id, data))
                                    update_online+=1

                            elif subnet['discoverSubnet'] == '1':
                                data = {'subnetId': subnet['id'], 'ip': ip, 'hostname': hostname, 'tag': f"{online_tag}", 'lastSeen': now()}
                                print(createPhpIpam(server, api_client, api_token, 'addresses', data))
                                add_online+=1

                    if addresses_list is not None and len(addresses_list) > 0:
                        for ip in addresses_list:
                            status = addresses_list[ip]
                            if status['excludePing'] or status['tag'] == offline_tag:
                                pass
                            elif ip not in hosts_list or (
                            'state' in hosts_list[ip] and
                            'state' in hosts_list[ip]['state'] and
                            hosts_list[ip]['state']['state'] == 'down'
                            ): # Offline
                                data = {'tag': f"{offline_tag}"}
                                print(updatePhpIpam(server, api_client, api_token, 'addresses', status['id'], data))
                                update_offline+=1

                if update_online + add_online + update_offline > 0:
                    print(f"Added: {add_online}, Changed: {update_online} online {update_offline} offline at {now()}")
                else:
                    print(f"No changes at {now()}")
                if subnet['discoverSubnet'] == '1':
                    now = now()
                    data = {'lastScan': now, 'lastDiscovery': now}
                else:
                    data = {'lastScan': now}
                updatePhpIpam(server, api_client, api_token, 'subnets', subnet['id'], data)
                updatePhpIpam(server, api_client, api_token, 'tools/scanagents', scanagent['id'], {'last_access': now()})
    time.sleep(sleep_seconds)
