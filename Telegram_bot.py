import threading
import time
import telegram.ext
import config
import AcuScan
import Acunetix
import logging
import concurrent.futures
import psutil
import json
import jwt
import requests
from concurrent.futures import ThreadPoolExecutor
from telegram import ParseMode, Update, InlineKeyboardButton, InlineKeyboardMarkup, ReplyKeyboardRemove
from telegram.ext import Updater, CommandHandler, CallbackContext, CallbackQueryHandler, ConversationHandler, MessageHandler, Filters

api_key = config.TELEGRAM_API_KEY
chat_id = config.ALLOWED_USER_ID
TOKEN_EXPIRATION = config.TOKEN_EXPIRATION
SECRET_KEY = config.SECRET_KEY
API_PORT = config.API_PORT
targets_to_scan = []
scan_target = ''
note_file_path = 'Logs/Notes.txt'
host = config.HOST
proxy_url = 'http://127.0.0.1:8080'
proxies = {
        'http': proxy_url,
        'https': proxy_url
    }

headers = {"X-Auth":config.ACUNETIX_API_KEY,"content-type": "application/json"}

updater = telegram.ext.Updater(api_key, use_context=True)
disp = updater.dispatcher

# Create a ThreadPoolExecutor
executor = concurrent.futures.ThreadPoolExecutor()

user_tokens = {}

def generate_token(user_id):
    payload = {
        'user_id': user_id,
    }
    if TOKEN_EXPIRATION is not None:
        payload['exp'] = time.time() + TOKEN_EXPIRATION
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def get_api_token(update: Update, context: CallbackContext) -> None:
    user_id = update.message.from_user.id
    token = generate_token(user_id)
    user_tokens[user_id] = token
    update.message.reply_text(f'Your API token: {token}')

# Enable logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)
logging.getLogger("telegram.vendor.ptb_urllib3.urllib3").setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

def error_handler(update, context):
    """Log any uncaught exceptions to the console."""
    logging.error(msg="Exception while handling an update:", exc_info=context.error)

def start_command(update: Update, context):
    update.message.reply_text('this is a test!')


def add_target_command(update: Update, context):
    user_id = update.message.from_user.id
    if(chat_id != user_id):
        update.message.reply_text('Sorry, you are not authorized to run this command!')
        return 0
    target = context.args[0] if context.args else None
    if not target:
        update.message.reply_text("Please provide the the target.")
        return
    update.message.reply_text(f'Added target: {target}!', disable_web_page_preview=True)
    # update.message.reply_text(f'{msg}')
    # msg = AcuScan.run_subfinder_httpx(target)
    threading.Thread(target=AcuScan.run_subfinder_httpx, args=(target,)).start()


def list_target_command(update: Update, context):
    user_id = update.message.from_user.id
    if(chat_id != user_id):
        update.message.reply_text('Sorry, you are not authorized to run this command!')
        return 0
    target_lists = 'List target not scan nuclei yet:\n'
    targets = AcuScan.get_targets_not_scan_nuclei()
    for target in targets:
        target_lists += f'`/start_scan {target}`\n'
    
    update.message.reply_text(f'{target_lists}\nUse command "/start\_scan <target>" to start scan on this target subdomains', parse_mode=ParseMode.MARKDOWN)


def print_subdomains_command(update: Update, context):
    user_id = update.message.from_user.id
    if(chat_id != user_id):
        update.message.reply_text('Sorry, you are not authorized to run this command!')
        return 0
    target = context.args[0] if context.args else None
    if not target:
        update.message.reply_text("Please provide the the target.")
        return
    count = 0
    list_subdomains = f'List subdomain of target {target}:\n'
    try:
        file_path = f'Target_logs/{target}/{target}_subdomains.txt'
        file_list_subdomains = open(file_path,"r")
        for line in file_list_subdomains:
            list_subdomains += f'{line.strip()}\n'
            count += 1
        update.message.reply_text(f'{list_subdomains}\nTotal: {count} subdomains.', disable_web_page_preview=True)
    except FileNotFoundError:
        update.message.reply_text('target not found! Add the target by using command /add_target', disable_web_page_preview=True)


def start_scan_command(update: Update, context):
    user_id = update.message.from_user.id
    if chat_id != user_id:
        update.message.reply_text('Sorry, you are not authorized to run this command!')
        return
    
    target = context.args[0] if context.args else None
    if not target:
        update.message.reply_text("Please provide the the target to scan, it can be a wildcard target or single target.")
        return

    # start scan acunetix imediatly for single target (currently skipping scan nuclei)
    if target.startswith('http') or target.startswith('https'):
        acu_target = [
            {
                "address" : f"{target}",
                "description" : "Single target auto scan"
            }
        ]
        
        target_id = Acunetix.AddTarget(acu_target,'')[0].get('target_id')
        Acunetix.StartScan(target_id, config.SCAN_PROFILE_ID)
        update.message.reply_text(f'Start acunetix scan on target {target}', disable_web_page_preview=True)
        msg = f'[Start Scan Acunetix] - {target}'
        AcuScan.write_logs(msg, AcuScan.target_log)

    else:
        targets = AcuScan.get_targets_not_scan_nuclei()
        
        if target not in targets:
            update.message.reply_text(f'Target {target} is not in the list. Add target to the list using command /add_target')
            return
    
    # Submit the scan task to the ThreadPoolExecutor
    update.message.reply_text(f'Scan started for target {target}.', disable_web_page_preview=True)
    # fix this in the future
    # executor.submit(AcuScan.run_nuclei, target)


def set_targets_command(update: Update, context):
    user_id = update.message.from_user.id
    if chat_id != user_id:
        update.message.reply_text('Sorry, you are not authorized to run this command!')
        return
    
    number_of_targets = context.args[0] if context.args else None
    if not number_of_targets:
        update.message.reply_text("Please provide the number of targets you wanto scan at the same time.")
        return
    
    try:
        config.NUMBER_OF_TARGETS_SIMULTANEOUSLY = int(number_of_targets)
    except:
        update.message.reply_text(f'Fail to set number of targets simultaneously to {number_of_targets}')

    update.message.reply_text(f'Set number of targets simultaneously for acunetix to: {config.NUMBER_OF_TARGETS_SIMULTANEOUSLY}')
    msg = f'[Config] - Set number of targets simultaneously for acunetix to: {config.NUMBER_OF_TARGETS_SIMULTANEOUSLY}'
    AcuScan.write_logs(msg, AcuScan.target_log)


def stop_vuln_command(update: Update, context):
    user_id = update.message.from_user.id
    if chat_id != user_id:
        update.message.reply_text('Sorry, you are not authorized to run this command!')
        return
    
    vuln_id = context.args[0] if context.args else None
    if not vuln_id:
        update.message.reply_text("Please provide Vulnerability ID.")
        return
    
    config.OUT_SCOPE_VULN_ACUNETIX.append(vuln_id)
    update.message.reply_text(f'Stop receiving noti for vuln {vuln_id}')
    msg = f"[Config] - Stop receive noti for vuln {vuln_id}"
    AcuScan.write_logs(msg, AcuScan.target_log)


def auto_abort_scan_false_command(update: Update, context):
    user_id = update.message.from_user.id
    if chat_id != user_id:
        update.message.reply_text('Sorry, you are not authorized to run this command!')
        return
    
    target = context.args[0] if context.args else None
    if not target:
        update.message.reply_text("Please provide target address or scan ID.")
        return
    
    if target.startswith('http://') or target.startswith('https://'):
        Acunetix.add_to_heavy_scan_acunetix_target_log(target_address=target, is_auto_stop=False)
    else:
        Acunetix.add_to_heavy_scan_acunetix_target_log(scan_id=target, is_auto_stop=False)
        
    msg = f'To set the auto stop back on this target use the command `\\auto_abort_scan_true {target}`'
    update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN)


def auto_abort_scan_true_command(update: Update, context):
    user_id = update.message.from_user.id
    if chat_id != user_id:
        update.message.reply_text('Sorry, you are not authorized to run this command!')
        return
    
    target = context.args[0] if context.args else None
    if not target:
        update.message.reply_text("Please provide target address or scan ID.")
        return
    
    if target.startswith('http://') or target.startswith('https://'):
        Acunetix.add_to_heavy_scan_acunetix_target_log(target_address=target, is_auto_stop=True)
    else:
        Acunetix.add_to_heavy_scan_acunetix_target_log(scan_id=target, is_auto_stop=True)

    msg = f'Set the auto stop scan acunetix for target: {target}'
    update.message.reply_text(msg)


def ram_command(update: Update, context):
    user_id = update.message.from_user.id
    if chat_id != user_id:
        update.message.reply_text('Sorry, you are not authorized to run this command!')
        return

    # Get system memory usage
    mem = psutil.virtual_memory()
    msg = f"Memory Usage Percentage: {mem.percent}%"
    update.message.reply_text(msg)

def get_processing_targets_command(update: Update, context):
    user_id = update.message.from_user.id
    if chat_id != user_id:
        update.message.reply_text('Sorry, you are not authorized to run this command!')
        return
    in_process_target = Acunetix.GetInProcessTargets('processing')
    list_in_process_targets = in_process_target.get('scans')
    target_left = Acunetix.GetTargetsLeft()
    processing_target = f'{len(list_in_process_targets)} / {config.NUMBER_OF_TARGETS_SIMULTANEOUSLY} simultaneously targets:\nTargets left: {target_left}\nScan time: {config.SCAN_TIME}\n\n'

    for target in list_in_process_targets:
        target_address = target.get('target').get('address')
        scan_id = target.get('scan_id')
        start_date = target.get('current_session').get('start_date')
        time_scaned = AcuScan.compare_datetime_with_current(start_date)
        vulns =  json.dumps(target.get('current_session').get('severity_counts'), indent=2)
        processing_target += (
            f'target: {target_address}\n' +
            f'Scan id: `{scan_id}`\n' +
            f'Time scaned: {time_scaned}\n' +
            f'List vuln:\n' +
            f'{vulns}\n\n' +
            '==========\n\n'
        )
    update.message.reply_text(processing_target, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True)


def stop_scan_acunetix_command(update: Update, context: CallbackContext) -> None:
    user_id = update.message.from_user.id
    if chat_id != user_id:
        update.message.reply_text('Sorry, you are not authorized to run this command!')
        return
    # Extract the scan ID from the command
    scan_id = context.args[0] if context.args else None
    
    if not scan_id:
        update.message.reply_text("Please provide a scan ID.")
        return
    
    # Prepare the inline keyboard with two buttons: Yes and No
    keyboard = [
        [InlineKeyboardButton("Yes", callback_data=f"stop_scan_yes:{scan_id}"),
         InlineKeyboardButton("No", callback_data="stop_scan_no")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    # Ask the user for confirmation using the inline keyboard
    update.message.reply_text("Are you sure you want to stop the scan?", reply_markup=reply_markup)
    

# Define the callback function for handling inline button clicks
def button_click_stop_scan(update: Update, context: CallbackContext) -> None:
    query = update.callback_query
    data = query.data.split(':')
    action = data[0]
    scan_id = data[1] if len(data) > 1 else None
    
    if action == 'stop_scan_yes':
        # Implement logic to stop the scan using the provided scan_id
        Acunetix.StopScan(scan_id=scan_id)
        Acunetix.delete_to_heavy_scan_acunetix_target_log(scan_id)
        address = Acunetix.GetDetailFromScanId(scan_id).get('target').get('address')
        query.edit_message_text(f'Successfull abort scan {address} - {scan_id}')
        msg = f'[Acunetix Scan] - Manual abort scan target {address}'
        AcuScan.write_logs(msg, AcuScan.target_log)
        query.edit_message_text(f"Stopping scan on target {address}...", disable_web_page_preview=True)
    else:
        query.edit_message_text("Cancel stop scan on the target.")

# def stop_scan_acunetix_command(update: Update, context: CallbackContext) -> None:
#     user_id = update.message.from_user.id
#     if chat_id != user_id:
#         update.message.reply_text('Sorry, you are not authorized to run this command!')
#         return
#     # Extract the scan ID from the command
#     scan_id = context.args[0] if context.args else None
    
#     if not scan_id:
#         update.message.reply_text("Please provide a scan ID.")
#         return

def get_list_vulns_command(update: Update, context: CallbackContext) -> None:
    user_id = update.message.from_user.id
    if chat_id != user_id:
        update.message.reply_text('Sorry, you are not authorized to run this command!')
        return
    # Extract the scan ID from the command
    update.message.reply_text('Getting list vulns. Wait for few second...')
    # serverity = context.args[0] if context.args else None
    # targets = context.args[1] if context.args else None

    args=update.message.text[15:]
    args = args.split()       
    serverity = args[0] if len(args) > 0 else None     
    targets= args[1]  if len(args) > 1 else None
    if serverity != None and targets == None and (serverity.startswith('https://') or serverity.startswith('http://')):
        targets = serverity
        serverity = '2,3,4'
    # if serverity != None and targets == None and not (serverity.startswith('https://') or serverity.startswith('http://')) :
    #     list_target_id_str = serverity
    # try:
    # print(serverity)
    list_targets_address = []
    # response = requests.get(f'{host}/api/v1/targets?l=100&q=text_search:*{targets.strip()};', headers=headers, verify=False, proxies=proxies)

    if not serverity and not targets:
        query = f'severity:2,3,4;target_id:;status:!ignored;status:!fixed;&s=severity:desc'
    else:
        if not serverity:
            serverity = ''
        if not targets:
            list_target_id_str = ''
        else:
            list_targets_address = targets.split(',')
            list_target_id = []
            for target in list_targets_address:
                response = requests.get(f'{host}/api/v1/targets?l=100&q=text_search:*{target.strip()};', headers=headers, verify=False)
                target_info = json.loads(response.text).get('targets')[0]
                target_id = target_info.get('target_id')
                list_target_id.append(target_id)
                
            list_target_id_str = ''
        try:
            for target_id in list_target_id:
                list_target_id_str += f'{target_id.strip()},'
        except:
            pass
        query = f'severity:{serverity};target_id:{list_target_id_str};status:!ignored;status:!fixed;&s=severity:desc'
    
    response = requests.get(f'{host}/api/v1/vulnerabilities?l=14&q={query}', headers=headers, verify=False)
    json_response = json.loads(response.text)
    if response.status_code == 400:
        msg = f'400 Bad Request\nYour querry: {query}\n{json_response}'
        update.message.reply_text(msg, disable_web_page_preview=True)
        return 0
    count_vuln = str(json_response.get('pagination').get('count'))
    List_vulns = json_response.get('vulnerabilities')
    if len(list_targets_address) != 0:
        List_vuln_str = f'Vulnerability of: {list_targets_address}\nTotal: {len(List_vulns)} vulns\n\n'
    else:
        List_vuln_str = f'All Vulnerability found\nTotal: {count_vuln} vulns\n\n'
    
    for vuln in List_vulns:
        vt_id = vuln.get('vt_id')
        if vt_id not in config.OUT_SCOPE_VULN_ACUNETIX:
            vuln_severity = vuln.get('severity')
            txt_severity = ''
            if vuln_severity == 1:
                txt_severity = '[Lows]'
            if vuln_severity == 2:
                txt_severity = '[Medium]'
            if vuln_severity == 3:
                txt_severity = '[High]'
            if vuln_severity == 4:
                txt_severity = '[Critical]'
            vuln_detail = (
                f"*{txt_severity} - {vuln.get('vt_name')} : ({vuln.get('confidence')} confidence)*\n" +
                f"Target: {vuln.get('affects_url')}\n" +
                f"For more detail: `/vuln_detail {vuln.get('vuln_id')}`\n" +
                f"To Stop receive noti for this vuln you can use command `/stop_vuln {vuln.get('vt_id')}`\n" +
                "----------\n"
            )
            List_vuln_str += vuln_detail
    # print(List_vuln_str)
    update.message.reply_text(List_vuln_str, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True)
    print(List_vuln_str)
    # except Exception as e:
    #     print(f'[ERROR]: get_list_vulns function\n{e}')
    #     AcuScan.write_logs(f'[ERROR]: get_list_vulns function\n {str(e)[:33]}', log_path=AcuScan.target_log)
    #     update.message.reply_text(f'Some thing went wrong in get_list_vulns. Error message: {str(e)[:333]}')

def convert_serverity(serverity: int):
    if serverity == 0:
        txt_severity = '[Information]'
    if serverity == 1:
        txt_severity = '[Lows]'
    if serverity == 2:
        txt_severity = '[Medium]'
    if serverity == 3:
        txt_severity = '[High]'
    if serverity == 4:
        txt_severity = '[Critical]'
    return txt_severity

def vuln_detail_command(update: Update, context):
    user_id = update.message.from_user.id
    if chat_id != user_id:
        update.message.reply_text('Sorry, you are not authorized to run this command!')
        return
    
    vuln_id = context.args[0] if context.args else None
    if not vuln_id:
        update.message.reply_text("Please provide a vuln ID")
        return
    
    response = requests.get(f'{host}/api/v1/vulnerabilities/{vuln_id}', headers=headers, verify=False)
    json_response = json.loads(response.text)

    references = json_response.get('references')
    references_txt = ''
    for reference in references:
        references_txt += f"[{reference.get('rel')}]({reference.get('href')})\n"
        pass

    vuln_severity = json_response.get('severity')
    txt_severity = convert_serverity(vuln_severity)


    vuln_details = Acunetix.get_vuln_details(vuln_id)
    msg = (f"*{txt_severity} - {json_response.get('vt_name')} : ({json_response.get('confidence')} confidence)*\n" +
        f"target: {json_response.get('affects_url')}\n" +
        "----------------------\n" +
        "details:\n" +
        f"CVSS Score: {json_response.get('cvss_score')}\n" +
        f"{json_response.get('cvss3')}\n\n" +
        f"{AcuScan.replace_markdown_message(AcuScan.html.unescape(vuln_details.get('details')[:333]))}...\n" +
        "----------------------\n" +
        "request:\n" +
        f"{AcuScan.replace_markdown_message(vuln_details.get('request'))}\n" +
        "----------------------\n" +
        "highlighted in response:\n" +
        f"{AcuScan.replace_markdown_message(vuln_details.get('highlighted_text'))}" +
        "----------------------\n" 
        f"references: \n{references_txt}" +
        "----------------------\n" 
    )
    update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True)


def vuln_type_command(update: Update, context):
    user_id = update.message.from_user.id
    if chat_id != user_id:
        update.message.reply_text('Sorry, you are not authorized to run this command!')
        return
    
    vuln_type = int(context.args[0]) if context.args else None
    if not vuln_type:
        update.message.reply_text('Please provide a vuln type (1-4).')
        return 0
    
    txt_severity = convert_serverity(vuln_type)

    list_msg = []
    msg = f'[{txt_severity}]:\n\n'
    for item in Acunetix.GetVulnType():
        if item.get('severity') == vuln_type:
            new_vuln_type = f"{AcuScan.replace_markdown_message(item.get('name'))}\n`/search_by_vuln_type {item.get('vt_id')}`\n`/stop_vuln {item.get('vt_id')}`\n\n"
            if len(msg + new_vuln_type) > 4096:
                list_msg.append(msg)
                msg = ''
            msg += new_vuln_type
    list_msg.append(msg)

    for msg in list_msg:
        update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True)
        time.sleep(1)


def search_by_vuln_type_command (update: Update, context):
    user_id = update.message.from_user.id
    if chat_id != user_id:
        update.message.reply_text('Sorry, you are not authorized to run this command!')
        return
    
    vuln_type_id = context.args[0] if context.args else None
    if not vuln_type_id:
        update.message.reply_text('Please provide a vuln type (1-4).')
        return 0

    list_vulns = Acunetix.GetLatestVuln(vt_id=vuln_type_id, severity='0,1,2,3,4')
    vt_name = list_vulns[0].get('vt_name')
    list_msg = []
    msg = f"List Vulnerabilities for {AcuScan.replace_markdown_message(vt_name)}:\n\n"
    for item in list_vulns:
        new_vuln_msg = (
            f"Affects URL: {AcuScan.replace_markdown_message(item.get('affects_url'))} ({item.get('confidence')} confidence)\n" +
            f"`/vuln_detail {AcuScan.replace_markdown_message(item.get('vuln_id'))}`\n\n"
        )
        if len(msg + new_vuln_msg) > 4096:
            list_msg.append(msg)
            msg = ''
        msg += new_vuln_msg
    list_msg.append(msg)
    for msg in list_msg:
        update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True)
        time.sleep(1)


def help_command(update: Update, context):
    user_id = update.message.from_user.id
    if chat_id != user_id:
        update.message.reply_text('Sorry, you are not authorized to run this command!')
        return
    update
    # Make sure _ is escape !
    help_msg = (
        "`/start`" + " - just a start !\n" +
        "`/help`" + " - help !\n" +
        "`/add_target`" + " - add wildcard target to find it subdomains.\n" +
        "`/start_scan`" + " - start scan on wildcard / single target\n" +
        "`/set_targets`" + " - Set number of targets simultaneously scan acunetix\n" +
        "`/list_target`" + " - list all the target add by /add\_target that not been scan nuclei\n" +
        "`/print_subdomains`" + " - print subdomains of target\n" +
        "`/stop_vuln`" + " - add vuln to list out scope\n" +
        "`/auto_abort_scan_true`" + " - set auto abort after 9 hours for target\n" +
        "`/auto_abort_scan_false`" + " - unset auto abort after 9 hours for target\n" +
        "`/ram`" + " - show system memory usage\n" +
        "`/get_processing_targets`" + " - list all the target have status proccessing acunetix\n" +
        "`/stop_scan_acunetix`" + " - stop an acunetix scan by scan\_id\n" +
        "`/get_list_vulns`" + " - get all the vuln by filter eg: '/get\_list\_vulns 2,3,4 https://example.com,https://google.com'\n" +
        "`/vuln_detail`" + " - get vuln detail by vuln id\n" +
        "`/vuln_type`" + " - get all scanned vulns by severity (1-4)\n" +
        "`/search_vuln`" + " - search for vuln has been scaned\n" +
        "`/manual_activate_auto_scan`" + " - Manual activate auto scan after it dead. Not sure if this work :)\n" +
        "`/notification`" + " - Enable or disable new vulnerabilities notifications from the bot\n" +
        "`/get_api_token`" + " - generate a new API token that can be used for authenticating requests to the associated API server" 
    )
    update.message.reply_text(help_msg, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True)


def read_note_command(update: Update, context):
    user_id = update.message.from_user.id
    if chat_id != user_id:
        update.message.reply_text('Sorry, you are not authorized to run this command!')
        return
    
    note = context.args[0] if context.args else None
    try:
        Notes = ''
        with open(note_file_path, 'r') as file:
            List_notes = file.readlines()
        if not note:
            for item in List_notes:
                Notes += f'{item}'
        else:
            try:
                for num in range(int(note)):
                    Notes += f'{List_notes[num]}'
            except IndexError as e:
                print(type(str(e)))
                print(f'{str(e)[:33]}...')
        update.message.reply_text(Notes, disable_web_page_preview=True)
    except FileNotFoundError as e:
        update.message.reply_text('There are currently no notes recorded')
    

def note_command(update: Update, context):
    update.message.reply_text("Please enter your note:")
    return 1

def save_note(update: Update, context):
    note = update.message.text
    if not note:
        update.message.reply_text("The note is empty. Please enter a valid note.")
        return 0
    AcuScan.write_logs(f'[Note]: {note}', note_file_path)
    update.message.reply_text("Note saved successfully.", reply_markup=ReplyKeyboardRemove())
    return ConversationHandler.END


def manual_activate_auto_scan_command(update: Update, context):
    if AcuScan.is_scan_dead:
        threading.Thread(target=AcuScan.get_new_vuln_acunetix).start()
        update.message.reply_text('Manual activate auto scan after it dead. Not sure if this work, good luck :v')
    else:
        update.message.reply_text('the auto scan function is not dead. OR... Something wrong here =))')


def search_vuln_command(update: Update, context):
    user_id = update.message.from_user.id
    if chat_id != user_id:
        update.message.reply_text('Sorry, you are not authorized to run this command!')
        return
    
    query = context.args[0] if context.args else None
    if not query:
        query = ''
    
    response = requests.get(f'{host}/api/v1/vulnerability_types?q=severity:{query};status:!ignored;status:!fixed', headers=headers, verify=False)
    json_response = json.loads(response.text)
    vulnerability_types = json_response.get('vulnerability_types')
    list_msg = []
    msg = f'List vulns for type {query}:\n\n'
    for vuln_type in vulnerability_types:
        new_msg = (
            f"[{convert_serverity(vuln_type.get('severity'))}] - {AcuScan.replace_markdown_message(vuln_type.get('name'))}\n" +
            f"`/search_by_vuln_type {vuln_type.get('vt_id')}`\n\n"
        )
        if (len(msg) + len(new_msg) > 4096):
            list_msg.append(msg)
            msg = ''
        msg += new_msg
    list_msg.append(msg)
    for msg in list_msg:
        update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True)
        time.sleep(1)

def notification_command(update: Update, context):
    user_id = update.message.from_user.id
    if(chat_id != user_id):
        update.message.reply_text('Sorry, you are not authorized to run this command!')
        return 0
    status = context.args[0] if context.args else None
    if not status:
        update.message.reply_text("Please provide `True` or `False` to set the status of notification.")
        return
    status = status.strip().lower() 
    if status == 'true':
        status = True
    elif status == 'false':
        status = False
    else:
        update.message.reply_text(f"Invalid input argument '{status}'. Expected 'True' or 'False'. Current notification status: {config.NOTIFICATION}")

    if isinstance(status, bool):
        config.NOTIFICATION = status
        update.message.reply_text(f'Set notification to {status}!')

def run_flask_api():
    from api import app  # Import the Flask app object from api.py
    app.run(host='0.0.0.0', port=API_PORT)

def run_telegram_bot():

    disp.add_handler(telegram.ext.CommandHandler("start", start_command))
    disp.add_handler(telegram.ext.CommandHandler("help", help_command))
    disp.add_handler(telegram.ext.CommandHandler("add_target", add_target_command))
    disp.add_handler(telegram.ext.CommandHandler("start_scan", start_scan_command))
    disp.add_handler(telegram.ext.CommandHandler("set_targets", set_targets_command))
    disp.add_handler(telegram.ext.CommandHandler("list_target", list_target_command))
    disp.add_handler(telegram.ext.CommandHandler("print_subdomains", print_subdomains_command))
    disp.add_handler(telegram.ext.CommandHandler("stop_vuln", stop_vuln_command))
    disp.add_handler(telegram.ext.CommandHandler("auto_abort_scan_true", auto_abort_scan_true_command))
    disp.add_handler(telegram.ext.CommandHandler("auto_abort_scan_false", auto_abort_scan_false_command))
    disp.add_handler(telegram.ext.CommandHandler("ram", ram_command))
    disp.add_handler(telegram.ext.CommandHandler("get_processing_targets", get_processing_targets_command))
    disp.add_handler(telegram.ext.CommandHandler("stop_scan_acunetix", stop_scan_acunetix_command))
    disp.add_handler(telegram.ext.CommandHandler("get_list_vulns", get_list_vulns_command))
    disp.add_handler(telegram.ext.CommandHandler("vuln_detail", vuln_detail_command))
    disp.add_handler(telegram.ext.CommandHandler("vuln_type", vuln_type_command))
    disp.add_handler(telegram.ext.CommandHandler("search_by_vuln_type", search_by_vuln_type_command))
    disp.add_handler(telegram.ext.CommandHandler("read_note", read_note_command))
    disp.add_handler(telegram.ext.CommandHandler("manual_activate_auto_scan", manual_activate_auto_scan_command))
    disp.add_handler(telegram.ext.CommandHandler("search_vuln", search_vuln_command))
    disp.add_handler(telegram.ext.CommandHandler("get_api_token", get_api_token))
    disp.add_handler(telegram.ext.CommandHandler("notification", notification_command))
    
    disp.add_handler(CallbackQueryHandler(button_click_stop_scan))
    note_handler = ConversationHandler(
        entry_points=[CommandHandler("note", note_command)],
        states={
            1: [MessageHandler(Filters.text & ~Filters.command, save_note)]
        },
        fallbacks=[]
    )
    disp.add_handler(note_handler)
    disp.add_error_handler(error_handler)

    updater.start_polling()
    updater.idle()


    # threading.Thread(target=AcuScan.get_new_vuln_acunetix).start()

def main() -> None:
    if config.API_SERVER:
        # Create a ThreadPoolExecutor to run both the Telegram bot and the Flask API
        with ThreadPoolExecutor(max_workers=2) as executor:
            executor.submit(run_telegram_bot)  # Start the Telegram bot
            executor.submit(run_flask_api)     # Start the Flask API
    else:
        run_telegram_bot()  # Only run the Telegram bot

if __name__ == "__main__":
    main()

help = """
/start: just a start !
/note: write a note
/read_note: retrive note, can add arg as number of line
/help: help !
/add_target: add wildcard target to find it subdomains.
/start_scan: start scan on wildcard / single target
/set_targets: Set number of targets simultaneously scan acunetix
/list_target: list all the target add by /add_target that not been scan nuclei
/print_subdomains: print subdomains of target
/stop_vuln: add vuln to list out of scope
/auto_abort_scan_true: set auto abort after 9 hours for target
/auto_abort_scan_false: unset auto abort after 9 hours for target
/ram: show system memory usage
/get_processing_targets: list all the target have status proccessing acunetix
/stop_scan_acunetix: stop an acunetix scan by scan_id
/get_list_vulns: get all the vuln by filter eg: /get_list_vulns 2,3,4 https://example.com, https://google.com
/vuln_detail: get vuln detail by vuln id
/vuln_type: get all scanned vulns by severity (1-4)
/search_vuln: search for vuln has been scaned
/manual_activate_auto_scan: Manual activate auto scan after it dead. Not sure if this work :)
/notification: Enable or disable new vulnerabilities notifications from the bot
/get_api_token: generate a new API token that can be used for authenticating requests to the associated API server
"""

