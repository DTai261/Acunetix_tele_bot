import requests
import config
import sys
import json
import urllib3
import os
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from datetime import datetime

sys.dont_write_bytecode = True

heavy_scan_acunetix_target_log = "Logs/heavy_scan_acunetix_target_log.json"
apikey = config.ACUNETIX_API_KEY
scan_profile = config.SCAN_PROFILE
number_of_target_simultaneously = config.NUMBER_OF_TARGETS_SIMULTANEOUSLY
is_check_simultaneously = True
host = config.HOST
proxy_url = 'http://127.0.0.1:8080'
proxies = {
        'http': proxy_url,
        'https': proxy_url
    }

headers = {"X-Auth":apikey,"content-type": "application/json"}

def AddTarget(ListTarget: list, group: list =None) -> list:
    if group == "":
        groups = []
    else:
        groups = [group] if group else []
    data = {
        "targets": ListTarget,
        "groups": groups
    }
    response = requests.post(host+"/api/v1/targets/add", data=json.dumps(data), headers=headers, verify=False)
    json_response = json.loads(response.text)
    targets = json_response.get('targets')
    # Return list of target
    return targets
    
def AddGroup(GroupName: str) -> str:
    count = 0
    while True:
        if count == 0:
            json_data = {
                'name': f'{GroupName}',
                'description': '',
            }
        else:
            json_data = {
                'name': f'{GroupName} ({count})',
                'description': '',
            }
        response = requests.post(f'{host}/api/v1/target_groups', headers=headers, json=json_data, verify=False)
        if (response.status_code != 409):
            json_response = json.loads(response.text)
            group_id = json_response.get('group_id')
            return group_id 
        else:
            count += 1

        if count > 10:
            print('[ERROR] - Some thing wrong in Acunetix.AddGroup function')
            return None
    
#Get target list by "never scan", target group, address. Output is the list of target. eg: [{address_1,target_id_1},{address_2,target_id_2}]
def GetListTarget(never_scan: str ='never_scanned', target_address: str =None, target_group: str =None) -> list:
    is_never_scan = ""
    text_search = "text_search:*"
    group_id = "group_id:"
    
    if(never_scan != None):
        is_never_scan = never_scan
    if(target_group != None):
        group_id = f'group_id:{target_group}'
    if(target_address != None):
        text_search = f'text_search:*{target_address}'

    query = f'{is_never_scan};{text_search};{group_id};'
    response = requests.get(f'{host}/api/v1/targets?l=20&q={query}', headers=headers, verify=False)
    json_response = json.loads(response.text)

    result_list = []

    for target in json_response.get("targets", []):
        address = target.get("address")
        target_id = target.get("target_id")

        if address and target_id:
            result_list.append({"address": address, "target_id": target_id})

    return result_list

# Return the number of targets left
def GetTargetsLeft() -> int:
    response = requests.get(f'{host}/api/v1/targets?l=1&q=never_scanned;', headers=headers, verify=False)
    json_response = json.loads(response.text)
    count = json_response.get('pagination').get('count')
    return count


def StartScan(target_id: str, profile_id: str) -> None:
    json_data = {
        'profile_id': f'{profile_id}',
        'incremental': 'false',
        'schedule': {
            'disable': 'false',
            'start_date': None,
            'time_sensitive': 'false',
        },
        'target_id': f'{target_id}',
    }

    response = requests.post(f'{host}/api/v1/scans', headers=headers, json=json_data, verify=False)
    if response.status_code == 409:
        print(f'[ERROR] - Acunetix.StartScan\n{json.loads(response.text)}')

def AddScanProfile() -> str:
    response = requests.post(f'{host}/api/v1/scanning_profiles', headers=headers, json=scan_profile, verify=False)
    json_response = json.loads(response.text)
    profile_id = json_response.get('profile_id')
    return profile_id

def SortBySeverity(data: list) -> list:
    return sorted(data, key=lambda x: x.get("severity", 0),reverse=True)


def GetVulnType() -> list:
    response = requests.get(f'{host}/api/v1/vulnerability_types?q=text_search:*', headers=headers, verify=False)
    json_response = json.loads(response.text).get('vulnerability_types')
    list_vuln_type = [{"name": item["name"], "vt_id": item["vt_id"], "severity": item["severity"]} for item in json_response]
    list_vuln_type = SortBySeverity(list_vuln_type)
    return list_vuln_type


def GetLatestVuln(LastSeen: str =None, severity: str ='2,3,4', vt_id: str ='') -> list:
    CursorsId = ''
    #format the lastseen value
    Formated_LastSeen = Format_DateTime(LastSeen)
    

    List_vulns = []
    is_latest = False
    while True:
        response = requests.get(f'{host}/api/v1/vulnerabilities?c={CursorsId}&l=100&q=vt_id:{vt_id};severity:{severity};date:>{Formated_LastSeen};status:!ignored;status:!fixed;&s=last_seen:desc', headers=headers, verify=False)
        json_data = json.loads(response.text)
        List_vuln = json_data.get('vulnerabilities')
        if is_latest == False:
            # print(List_vuln[0].get('last_seen'))
            try:
                lastest = Format_DateTime(List_vuln[0].get('last_seen'))
                UpdateLogFile(lastest)
            except IndexError:
                pass
            is_latest= True

        List_vuln_filtered = [
            {
                "affects_url": item["affects_url"], 
                "severity" : item["severity"],
                "confidence": item["confidence"], 
                "target_id": item["target_id"],
                "vt_id": item["vt_id"],
                "vt_name": item["vt_name"],
                "vuln_id": item["vuln_id"]

            } 
            for item in List_vuln
        ]

        List_vulns.extend(List_vuln_filtered)

        Cursors_list = json_data.get('pagination').get('cursors')
        if len(Cursors_list) > 1:
            CursorsId = Cursors_list[1]
        if len(Cursors_list) == 1:
            break
    
    return List_vulns


def Format_DateTime(LastSeen: str) -> str:
    Formated_LastSeen = ''
    if LastSeen != None:
        plus_index = LastSeen.find('+')
        if plus_index != -1:
            Formated_LastSeen = LastSeen[:plus_index] + 'Z'
        else:
            Formated_LastSeen = LastSeen
    return Formated_LastSeen

def UpdateLogFile(new_datetime: str) -> None:
    log_file_path = "Logs/last_seen_acunetix.log"

    try:
        # Read the current datetime from the log file
        with open(log_file_path, 'r') as file:
            current_datetime_str = file.read().strip()

        if not current_datetime_str:
            # If the file is empty, write the new datetime
            with open(log_file_path, 'w') as file:
                file.write(new_datetime)
        else:
            # Parse datetimes
            current_datetime = datetime.strptime(current_datetime_str, "%Y-%m-%dT%H:%M:%S.%fZ")
            new_datetime_obj = datetime.strptime(new_datetime, "%Y-%m-%dT%H:%M:%S.%fZ")

            # Check if the new datetime is later than the current datetime
            if new_datetime_obj > current_datetime:
                # Overwrite the log file with the new datetime
                with open(log_file_path, 'w') as file:
                    file.write(new_datetime)
            else:
                pass

    except FileNotFoundError:
        # If the log file doesn't exist, create it with the given datetime
        with open(log_file_path, 'w') as file:
            file.write(new_datetime)

#status: completed, processing, ...
def GetInProcessTargets(status: str) -> dict:
    response = requests.get(f'{host}/api/v1/scans?l=20&q=status:{status};', headers=headers,verify=False)
    json_response = json.loads(response.text)
    return json_response
    

def CheckScanProfile() -> str:
    profile = False
    response = requests.get(f'{host}/api/v1/scanning_profiles', headers=headers, verify=False)
    if response.status_code != 409:
        scanning_profiles = json.loads(response.text).get('scanning_profiles')
        for scan_profile in scanning_profiles:
            if scan_profile.get('name') == 'AcuScan Auto Profile':
                profile = True
    else:
        print(f'[ERROR] - CheckScanProfile function')
    profile_id = None
    if not profile:
        profile_id = AddScanProfile()
    print('AcuScan Auto Profile is loaded')
    return profile_id


def get_vuln_details(vuln_id: str) -> dict:
    response = requests.get(f'{host}/api/v1/vulnerabilities/{vuln_id}',headers=headers,verify=False)
    json_response = json.loads(response.text)
    highlights = json_response.get('highlights')
    details = json_response.get('details')
    request = json_response.get('request')

    response = requests.get(f'{host}/api/v1/vulnerabilities/{vuln_id}/http_response',headers=headers,verify=False)
    http_response = response.text

    highlighted_text = ""
    for highlight in highlights:
        index = highlight.get("index", 0)
        length = highlight.get("length", 0)
        if(length > 100):
            break
        if len(http_response) <= 100:
            index -= 10
            length += 10
        if len(http_response) > 100 :
            index -= 20
            length += 20
        highlighted_text += f'{http_response[index:index+length]}\n'

    if highlighted_text == "":
        highlighted_text = f"The highlighted is too long for the message to handle\n"

    Vuln_detail ={
        "highlighted_text" : highlighted_text,
        "details" : details,
        "request" : request
    }
    return Vuln_detail


def GetTargetScanInfo(target_address: str=None, target_id: str=None) -> dict:
    if target_id == None:
        response = requests.get(f'{host}/api/v1/targets?l=100&q=text_search:*{target_address};', headers=headers, verify=False)
        target_info = json.loads(response.text).get('targets')[0]
        target_id = target_info.get('target_id')
    response = requests.get(f'{host}/api/v1/scans?l=20&q=status:processing;target_id:{target_id};', headers=headers, verify=False)
    json_response = json.loads(response.text)
    return json_response


def StopScan(target_address: str=None, scan_id: str=None) -> None:
    if scan_id == None:
        response = requests.get(f'{host}/api/v1/targets?l=100&q=text_search:*{target_address};', headers=headers, verify=False)
        target_info = json.loads(response.text).get('targets')[0]
        scan_id = target_info.get('target_id')
    json_data = {}
    requests.post(f'{host}/api/v1/scans/{scan_id}/abort', headers=headers, json=json_data, verify=False)

# StopScan(target_id='18361c3d-2a75-41a7-9883-e9345dd31716')
# print(GetTargetScanInfo(target_id='18361c3d-2a75-41a7-9883-e9345dd31716'))
    
def GetDetailFromScanId(scan_id: str) -> dict:
    response = requests.get(f'{host}/api/v1/scans/{scan_id}', headers=headers, verify=False)
    json_response = json.loads(response.text)
    return json_response

def add_to_heavy_scan_acunetix_target_log(scan_id: str=None, target_id: str = None, target_address: str=None, is_remind: str=True, is_auto_stop: str=True) -> None:
    if scan_id == None:
        response = requests.get(f'{host}/api/v1/targets?l=100&q=text_search:*{target_address};', headers=headers, verify=False)
        target_info = json.loads(response.text).get('targets')[0]
        scan_id = target_info.get('target_id')
    # Check if the file exists
    if not os.path.exists(heavy_scan_acunetix_target_log):
        # Create a new file with initial data if it does not exist
        data = {
            'heavy_targets' : {
                f'{scan_id}': {
                    'address' : target_address,
                    'target_id' : target_id,
                    'is_remind' : is_remind,
                    'is_auto_stop': is_auto_stop
                }
            }
        }
        with open(heavy_scan_acunetix_target_log, 'w') as file:
            json.dump(data, file, indent=4)
    else:
        # Read the existing data from the file
        with open(heavy_scan_acunetix_target_log, 'r') as file:
            data = json.load(file)
        
        if scan_id not in data['heavy_targets']:
            data['heavy_targets'][scan_id] = {
                'address': target_address,
                'target_id' : target_id,
                'is_remind': is_remind,
                'is_auto_stop': is_auto_stop
            }
        else:
            # Add the new target with the specified is_scan_nuclei value
            data['heavy_targets'][scan_id]['is_remind'] = is_remind
            data['heavy_targets'][scan_id]['is_auto_stop'] = is_auto_stop
        
        # Write the updated data back to the file
        with open(heavy_scan_acunetix_target_log, 'w') as file:
            json.dump(data, file, indent=4)


def delete_to_heavy_scan_acunetix_target_log(target_to_delete: str) -> None:
    # Read the data from the file
    with open(heavy_scan_acunetix_target_log, 'r') as file:
        data = json.load(file)
    
    # Delete the target if it exists
    if target_to_delete in data['heavy_targets']:
        del data['heavy_targets'][target_to_delete]
    
    # Write the updated data back to the file
    with open(heavy_scan_acunetix_target_log, 'w') as file:
        json.dump(data, file, indent=4)
