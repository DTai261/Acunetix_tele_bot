import os
import subprocess
import config
import json
import Acunetix
from datetime import datetime
# from Telegram_bot import send_message
# import Telegram_bot
import telegram.ext
from telegram import ParseMode
import threading
import time
import html
import re

target_log = "Logs/target.log"
current_target_log = "Logs/current_target.json"
heavy_scan_acunetix_target_log = "Logs/heavy_scan_acunetix_target_log.json"
out_scope_vuln_nuclei = config.OUT_SCOPE_VULN_NUCLEI
out_scope_vuln_acunetix = config.OUT_SCOPE_VULN_ACUNETIX

api_key = config.TELEGRAM_API_KEY
chat_id = config.ALLOWED_USER_ID
profile_id = config.SCAN_PROFILE_ID
config.NUMBER_OF_TARGETS_SIMULTANEOUSLY
is_check_simultaneously = True
is_scan_dead = False

updater = telegram.ext.Updater(api_key, use_context=True)
disp = updater.dispatcher

def send_message(msg: str, updater=updater) -> None:
    try:
        updater.bot.send_message(chat_id=chat_id, text=msg, disable_web_page_preview=True)
    except Exception as e:
        print(f'[ERROR] - send_message function\n{e}')
        time.sleep(1)
        updater = telegram.ext.Updater(api_key, use_context=True)
        updater.bot.send_message(chat_id=chat_id, text=msg, disable_web_page_preview=True)

# Send markdown message to user: *Bold* , _italic_ , `click to copy` , [link](https://example.com)
def send_message_markdown(msg: str, updater=updater) -> None:
    try:
        updater.bot.send_message(chat_id=chat_id, text=msg, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True)
    except Exception as e:
        print(f'[ERROR] - send_message_markdown function\n{e}')
        time.sleep(1)
        updater = telegram.ext.Updater(api_key, use_context=True)
        updater.bot.send_message(chat_id=chat_id, text=msg, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True)

def send_html_message(html_content: str) -> None:
    modified_html_content = html_content.replace('<span ', '<span class="tg-spoiler" ')
    modified_html_content = modified_html_content.replace('<br/>', '\n')
    modified_html_content = re.sub(r'<\s*p[^>]*>', '', modified_html_content)
    modified_html_content = re.sub(r'<\s*/\s*p\s*>', '', modified_html_content)
    try:
        updater.bot.send_message(chat_id=chat_id, text=modified_html_content, parse_mode=ParseMode.HTML, disable_web_page_preview=True)
    except Exception as e:
        print(f'[ERROR] - send_html_message\n{e}')


def write_logs(message: str, log_path: str) -> None:
    current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if not os.path.exists(log_path):
        # Create the log file if it doesn't exist
        with open(log_path, "w") as f:
            f.write("")
    with open(log_path, "r") as f:
        content = f.read()
    new_content = f"[{current_datetime}] : {message}\n{content}"
    with open(log_path, "w") as f:
        f.write(new_content)
    pass


def get_targets_not_scan_nuclei() -> list:
    false_targets = []
    # Read the data from the file
    with open(current_target_log, 'r') as file:
        data = json.load(file)
    
    # Collect targets with "is_scan_nuclei" set to false
    for target, properties in data['current_target'].items():
        if not properties['is_scan_nuclei']:
            false_targets.append(target)
    
    return false_targets


def add_to_current_target_log(new_target: str, is_scan_nuclei: bool) -> None:
    # Check if the file exists
    if not os.path.exists(current_target_log):
        # Create a new file with initial data if it does not exist
        data = {
            "current_target": {
                new_target: {"is_scan_nuclei": is_scan_nuclei}
            }
        }
        with open(current_target_log, 'w') as file:
            json.dump(data, file, indent=4)
    else:
        # Read the existing data from the file
        with open(current_target_log, 'r') as file:
            data = json.load(file)
        
        # Add the new target with the specified is_scan_nuclei value
        data['current_target'][new_target] = {"is_scan_nuclei": is_scan_nuclei}
        
        # Write the updated data back to the file
        with open(current_target_log, 'w') as file:
            json.dump(data, file, indent=4)


def delete_from_current_target_log(target_to_delete: str) -> None:
    # Read the data from the file
    with open(current_target_log, 'r') as file:
        data = json.load(file)
    
    # Delete the target if it exists
    if target_to_delete in data['current_target']:
        del data['current_target'][target_to_delete]
    
    # Write the updated data back to the file
    with open(current_target_log, 'w') as file:
        json.dump(data, file, indent=4)


def is_out_scope_vuln(string: str) -> bool:
    for item in out_scope_vuln_nuclei:
        if item in string:
            return True
    return False

def check_file(file_path: str) -> bool:
    # Check if the file exists
    if os.path.exists(file_path):
        # Check if the file is empty
        if os.path.getsize(file_path) < 3:
            return False
        else:
            return True
    else:
        return False
        
def run_subfinder_httpx(target: str) -> None:
    try:
        target_count = 0
        print(f'Start finding subdomain for {target}... ')
        send_message(f'Start finding subdomain for {target}... ')
        # Create the directory for the target if it doesn't exist
        target_directory = os.path.join("Target_Logs", target)
        os.makedirs(target_directory, exist_ok=True)
        output_file_path = os.path.join(target_directory, f"{target}_subdomains.txt")

        if not check_file(output_file_path):
            pass
            # Run the command and capture its output
            command = f"subfinder -d {target} --silent | httpxx --silent"
            try:
                # output = subprocess.check_output(command, shell=True, text=True)
                process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                with open(output_file_path, "w") as f:
                    for line in process.stdout:
                        f.write(line)  # Write each line to the file
                        target_count += 1
            except subprocess.CalledProcessError as e:
                print(f"Error: {str(e)[:33]}")
                log_msg = f'[__ERROR__] - {target} - {str(e)[:33]}'
                return
            
            # Write to log file
            log_msg = f'[Scan Subdomain] - {target}'
            print(f'Done find subdomains for {target}.')
            write_logs(log_msg, target_log)
        else:
            with open(output_file_path, 'r') as file:
                target_count = len(file.readlines())
        add_to_current_target_log(target, False)

        group_id = Acunetix.AddGroup(f'{target} subdomains')
        Add_Acunetix_targets(target, f'Auto Scan tool for {target}', group_id)
        # config_file_path = os.path.join(target_directory, f"Is_Scan_Nuclei.0")
        if target_count == 0:
            send_message(f'there is no subdomain for this target: {target}')
        if target_count == 1:
            send_message(f'there is 1 subdomain for this target: {target}')
        if target_count > 1:
            send_message(f'there are {target_count} subdomains for this target: {target}')
        send_message_markdown(f'Use command `/start_scan {target}` to start scan Acunetix on target')
    except Exception as  e:
        print(f'[ERROR] - run_subfinder_httpx\n {str(e)[:33]}')
        write_logs(f'[ERROR] - run_subfinder_httpx: {str(e)[:33]}', target_log)
        send_message(f'[ERROR] - run_subfinder_httpx\n {str(e)[:33]}')
    # threading.Thread(target=run_nuclei, args=(target,)).start()


def run_nuclei(target: str) -> None:
    print(f'Start scanning Nuclei for {target}...')
    log_msg = f'[Start Nuclei Scan] - {target}'
    write_logs(log_msg, target_log)
    if target.startswith('http') or target.startswith('https'):
        target_directory = "Target_Logs/Single_targets"
        command = f"nuclei -u {target} -as -nc"
        output_file_path = os.path.join(target_directory, f"{target.replace('://', '_')}_nuclei_scan_result.txt")
    else:
        target_directory = os.path.join("Target_Logs", target)
        target_file_path = os.path.join(target_directory, f"{target}_subdomains.txt")
        command = f"nuclei -l {target_file_path} -as -nc"
        output_file_path = os.path.join(target_directory, f"{target}_nuclei_scan_result.txt")
    
    send_message('Start scanning Nuclei...')
    list_vuln = ''
    is_vuln = False
    # Define the output file path
    

    # Run the command and capture its output incrementally
    # command = f"nuclei -l {target_file_path} -as -nc -o {output_file_path}"
    try:
        print(command)
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print('test123123')
        print(process)
        with open(output_file_path, "w") as f:
            for line in process.stdout:
                if '[critical]' in line:
                    is_vuln = True
                    list_vuln += (f'[Nuclei Scan] - {line.strip()}\n')
                    vuln_msg = f'CRITICAL VULN for {target}: {line.strip()}'
                    send_message(vuln_msg)
                if '[high]' in line:
                    is_vuln = True
                    list_vuln += (f'[Nuclei Scan] - {line.strip()}\n')
                    vuln_msg = f'HIGH VULN for {target}: {line.strip()}'
                    send_message(vuln_msg)
                if '[medium]' in line and not is_out_scope_vuln(line):
                    is_vuln = True
                    list_vuln += (f'[Nuclei Scan] - {line.strip()}\n')
                    vuln_msg = f'MEDIUM VULN for {target}: {line.strip()}'
                    send_message(vuln_msg)
                f.write(line)  # Write each line to the file
    except subprocess.CalledProcessError as e:
        # Handle any errors if the command fails
        print(f"Error: {e}")
        log_msg = f'[__ERROR__] - {target} - {e}'
        return
    
    add_to_current_target_log(target, True)
    log_msg = f'[Done Nuclei Scan] - {target}'
    write_logs(log_msg,target_log)
    print(f'Done Scan Nuclei for {target}')
    if is_vuln:
        send_message(f'List Vuln from Medium to Critical:\n{list_vuln}')
    else:
        send_message(f'There is no Medium, High, or Critical vuln for the target {target}')

def Add_Acunetix_targets(target: str, description :str, group_id=None) -> None:
    target_lists = []
    target_directory = os.path.join("Target_Logs", target)
    target_file_path = os.path.join(target_directory, f"{target}_subdomains.txt")
    file = open(target_file_path,'r')
    for line in file:
        target = {}
        target['address'] = line.strip()
        target['description'] = description
        target_lists.append(target)
    
    Acunetix.AddTarget(target_lists, group_id)


def compare_datetime_with_current(datetime_str: str) -> int:
    # Convert the datetime string to a datetime object
    given_datetime = datetime.fromisoformat(datetime_str[:-6])
    current_datetime = datetime.utcnow()
    time_difference = current_datetime - given_datetime
    hours_difference = time_difference.total_seconds() / 3600

    return int(hours_difference)

def replace_markdown_message(msg: str) -> str:
    msg = msg.replace('*', '\*')
    msg = msg.replace('_', '\_')
    msg = msg.replace('`', '\`')
    msg = msg.replace('[', '\[')
    msg = msg.replace('<strong>', '')
    msg = msg.replace('</strong>', '')
    msg = msg.replace('<li>', '\n')
    msg = msg.replace('</li>', '')
    msg = msg.replace('<ul>', '')
    msg = msg.replace('</ul>', '')
    msg = msg.replace('<br/>', '\n')
    # msg = msg.replace(']', '\]')
    return msg

def get_new_vuln_acunetix() -> None:
    global profile_id
    added_profile_id = Acunetix.CheckScanProfile()
    if added_profile_id != None:
        send_message_markdown(f'Created scan profile. Remember to add it to the config file: `{profile_id}`')
        profile_id = added_profile_id
    is_scanning = False
    heavy_target_log = None
    global is_scan_dead
    # try:
    while True:
        try:
            is_scan_dead = False
            file = open("Logs/last_seen_acunetix.log")
            last_seen = file.read().strip()
            List_Latest_vulns = Acunetix.GetLatestVuln(last_seen)
            in_process_target = Acunetix.GetInProcessTargets('processing')
            queued_target = Acunetix.GetInProcessTargets('queued')

            list_in_process_targets = in_process_target.get('scans')
            
            # Check time scan on the target and auto abort after 24/(pre-define) hours
            for target in list_in_process_targets:
                target_id = target.get('target_id')
                scan_id = target.get('scan_id')
                target_scan_info = Acunetix.GetTargetScanInfo(target_id=target_id)
                target_address = target_scan_info.get('scans')[0].get('target').get('address')
                target_start_date = target_scan_info.get('scans')[0].get('current_session').get('start_date')
                target_time_scan = compare_datetime_with_current(target_start_date)
                target_vulns = target_scan_info.get('scans')[0].get('current_session').get('severity_counts')

                try:
                    heavy_target_log = json.loads(open(heavy_scan_acunetix_target_log,'r').read()).get('heavy_targets')
                    with open(heavy_scan_acunetix_target_log, 'r') as file:
                        data = json.load(file)
                    
                    if scan_id in data['heavy_targets']:
                        is_remind = heavy_target_log.get(scan_id).get('is_remind')
                        is_auto_stop = heavy_target_log.get(scan_id).get('is_auto_stop')
                except FileNotFoundError:
                    heavy_target_log = None

                if target_time_scan > (config.SCAN_TIME - 1):
                    Acunetix.add_to_heavy_scan_acunetix_target_log(scan_id=scan_id, target_id=target_id, is_remind=True, target_address=target_address)
                if target_time_scan % (config.SCAN_TIME - 1) == 0 and target_time_scan != 0:
                    Acunetix.add_to_heavy_scan_acunetix_target_log(scan_id=scan_id, target_id=target_id, is_remind=False, target_address=target_address)
                    heavy_target_log = json.loads(open(heavy_scan_acunetix_target_log,'r').read()).get('heavy_targets')
                    # print(heavy_target_log)
                    is_remind = heavy_target_log.get(scan_id).get('is_remind')
                    is_auto_stop = heavy_target_log.get(scan_id).get('is_auto_stop')
                    if is_remind and is_auto_stop:
                        Acunetix.add_to_heavy_scan_acunetix_target_log(scan_id=scan_id, is_remind=False)
                        msg = (f'target {target_address} is running for {config.SCAN_TIME - 1} hours now, consider to stop it using command: \n`\stop_scan_acunetix {scan_id}`' +
                            f'\n\nThe tool will auto stop the scan on target after 1 hour from now, cancel auto stop on this target using command: \n`\\auto_abort_scan_false {scan_id}`' +
                            f'\n\nList vuln:\n{json.dumps(target_vulns, indent=2)}')
                        send_message_markdown(msg)
                        write_logs(f'[Acunetix Scan] - Alert auto abort on target {target_address} after {target_time_scan} hour(s)', target_log)
                if target_time_scan >= config.SCAN_TIME and heavy_target_log != None:
                    try:
                        if heavy_target_log.get(scan_id).get('is_auto_stop'):
                            msg = (
                                f'Stop Acunetix scan for {target_address}\nList vuln:\n{json.dumps(target_vulns, indent=2)}\n'+
                                f"For more detail, use the command:\n`/get_list_vulns {target_address}`"
                                )
                            send_message_markdown(msg)
                            Acunetix.StopScan(scan_id=scan_id)
                            Acunetix.delete_to_heavy_scan_acunetix_target_log(scan_id)
                            write_logs(f'[Acunetix Scan] - Auto abort scan target {target_address}', target_log)
                    except Exception as e:
                        print(f'[Error] - get_new_vuln_acunetix - Try to stop scan\n{e}')

                # prevent rate limit from Telegram
                time.sleep(1)
            # get the lastest vuln and send it to user
            for vuln in List_Latest_vulns:

                vt_id = vuln.get('vt_id')
                if vt_id not in config.OUT_SCOPE_VULN_ACUNETIX:
                    msg = ''
                    affects_url = vuln.get('affects_url')
                    confidence = vuln.get('confidence')
                    vt_name = vuln.get('vt_name')
                    vuln_id = vuln.get('vuln_id')
                    severity = vuln.get('severity')
                    txt_severity = ''
                    if severity == 2:
                        txt_severity = '[Medium]'
                    if severity == 3:
                        txt_severity = '[High]'
                    if severity == 4:
                        txt_severity = '[Critical]'
                    
                    vuln_details = Acunetix.get_vuln_details(vuln_id)
                    msg = (f"{txt_severity} - {vt_name} : ({confidence} confidence)\n" +
                        f"target: {affects_url}\n" +
                        "----------------------\n" +
                        "details:\n" +
                        f"{replace_markdown_message(html.unescape(vuln_details.get('details')[:333]))}\n" + # prevent eror when the message too long and the bot can't handler it
                        "----------------------\n" +
                        "request:\n" +
                        f"{vuln_details.get('request')}\n" +
                        "----------------------\n" +
                        "highlighted in response:\n" +
                        f"{vuln_details.get('highlighted_text')[:1000]}" +
                        "----------------------\n" 
                    )
                    msg = replace_markdown_message(msg)
                    msg += f'To Stop receive noti for this vuln you can use command `/stop_vuln {vt_id}`'

                    # except telegram.error.BadRequest:
                    send_message_markdown(msg)
                # prevent rate limit from Telegram
                time.sleep(1) 
            
            count = in_process_target.get('pagination').get('count') + queued_target.get('pagination').get('count')
            target_list = Acunetix.GetListTarget()
            if(len(target_list) != 0):
                is_scanning = True
            else:
                is_scanning = False

            if count < config.NUMBER_OF_TARGETS_SIMULTANEOUSLY and is_scanning:
                print(f'{count} - {config.NUMBER_OF_TARGETS_SIMULTANEOUSLY} - {is_scanning} - {is_scan_dead}')
                for i in range(config.NUMBER_OF_TARGETS_SIMULTANEOUSLY - count):
                    try:
                        target_id = target_list[i].get('target_id')
                        address = target_list[i].get('address')
                        Acunetix.StartScan(target_id, profile_id)
                        msg = f'[Acunetix Scan] - Start scan target {address}'
                        write_logs(msg, target_log)
                    except Exception as e:
                        print(f'[ERROR] - check line 418\n{e}...')
                        # send_message(f'[ERROR] - check line 418{str(e)[:33]}...')
                        pass
                    time.sleep(1)
            if len(target_list) == 0 and is_scanning:
                is_scanning = False
                msg = 'Out of target for acunetix scan !'
                send_message(msg)
                write_logs(f'[Acunetix Scan] - Out of target !', target_log)

            time.sleep(60)
        except Exception as e:
            print(f'[ERROR]: get_new_vuln_acunetix function\n{e}')
            write_logs(f'[ERROR] - {str(e)[:33]}...', target_log)
            send_message(f'[ERROR] - {str(e)[:33]}...')
            is_scan_dead = True
            updater = telegram.ext.Updater(api_key, use_context=True)

threading.Thread(target=get_new_vuln_acunetix).start()
# write_logs('test 12312', 'Logs/Notes.txt')
# run_nuclei('http://testphp.vulnweb.com/')