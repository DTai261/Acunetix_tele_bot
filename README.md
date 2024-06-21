<h1 align="center">
    Acunetix telegram bot
  <br>
</h1>

<h4 align="center">  Mining URLs from dark corners of Web Archives for bug hunting/fuzzing/further probing </h4>

<p align="center">
  <a href="#about">📖 About</a> •
  <a href="#features">📋 Features</a> •
  <a href="#installation">🏗️ Installation</a> •
  <a href="#usage">⛏️ Usage</a> •
  <a href="#examples">🚀 Examples</a> 
</p>


## About
The `Acunetix telegram bot` is a powerful and convenient Telegram bot designed to manage and automate your Acunetix vulnerability scans. This bot allows you to control your Acunetix scans directly from your Telegram account through simple commands.


## Features
- Automated Target Addition: Easily add new targets to your Acunetix scan queue via Telegram commands.
- Real-Time Vulnerability Alerts: Receive instant notifications on Telegram whenever new vulnerabilities are discovered during scans.
- Detailed Vulnerability Information: Get comprehensive details about each detected vulnerability directly in your Telegram chat, enabling quick assessment and action.
- Convenient Scan Management: Start, stop, and manage your scans with simple and intuitive Telegram commands.

## Installation
**Prerequire**:
You must be install the following tools first: [subfinder](https://github.com/projectdiscovery/subfinder), [httpx](https://github.com/projectdiscovery/httpx)<sup><a href="#1">(1)</a></sup>, [nuclei](https://github.com/projectdiscovery/nuclei)<sup><a href="#2">(2)</a>, [notify](https://github.com/projectdiscovery/notify)

To install `Acunetix telegram bot`, follow these steps:
```sh
git clone https://github.com/DTai261/Acunetix_tele_bot
cd Acunetix_tele_bot
pip install -r requirements.txt

# Edit the file config.py then run the bot:
python Telegram_bot.py
```

## Usage

The following command are use for control the acunetix scan using telegram. More details in the <a href='#example'>example</a>. <br>
`/start`: just a start !<br>
`/note`: write a note<br>
`/read_note`: retrive note, can add arg as number of line<br>
`/help`: help !<br>
`/add_target`: add wildcard target to find it subdomains.<br>
`/start_scan`: start scan on wildcard / single target<br>
`/set_targets`: Set number of targets simultaneously scan acunetix<br>
`/list_target`: list all the target add by `/add_target` that not been scan nuclei<br>
`/print_subdomains`: print subdomains of target<br>
`/stop_vuln`: add vuln to list out of scope<br>
`/auto_abort_scan_true`: set auto abort scan after x hours for all targets (default)<br>
`/auto_abort_scan_false`: unset auto abort scan after x hours for all targets<br>
`/ram`: show system memory usage<br>
`/get_processing_targets`: list all the target have status proccessing acunetix<br>
`/stop_scan_acunetix`: stop an acunetix scan by scan_id<br>
`/get_list_vulns`: get all the vuln by filter eg: `/get_list_vulns 2,3,4 https://example.com, https://google.com`<br>
`/vuln_detail`: get vuln detail by vuln id<br>
`/vuln_type`: get all scanned vulns by severity (1-4)<br>
`/search_vuln`: search for vuln has been scaned<br>
`/manual_activate_auto_scan`: Manual activate auto scan after it dead. Not sure if this work :)<br>

## Example

### `/add_target`
When user provide domain target, the bot will scan subdomain using subfinder and httpx then add them to the Acunetix target list.
<table>
  <tr>
    <td>
      <img src="https://raw.githubusercontent.com/DTai261/Acunetix_tele_bot/main/attachments/add_target_1.png" width="600px;" alt="1"/>
      <br />
      <br />
      <code>/add_target &lt;domain&gt;</code>
      <br />
    </td>
    <td>
        <img src="https://raw.githubusercontent.com/DTai261/Acunetix_tele_bot/main/attachments/add_target_2.png" width="600px;" alt="2"/>
        <br>
        <br>
      subdomain will be save to <code>Target_Logs/&lt;domain&gt;/&lt;domain&gt;_subdomain.txt
    </td>
  </tr>
</table>
<img src=https://raw.githubusercontent.com/DTai261/Acunetix_tele_bot/main/attachments/add_target_3.png alt="3">
<br>

### `/print_subdomains`
  <table>
    <tr>
      <td>
        <img src="https://raw.githubusercontent.com/DTai261/Acunetix_tele_bot/main/attachments/print_subdomain_1.png" alt="4"/>
        <br>
        <code>/print_subdomains &lt;domain&gt;</code>
        <br />
      </td>
    </tr>
  </table>

### `/start_scan`
Add single target to Acunetix scan list and scan it immediately.
  <table>
    <tr>
      <td>
        <img src="https://raw.githubusercontent.com/DTai261/Acunetix_tele_bot/main/attachments/start_scan_1.png" alt="5"/>
        <br>
        <code>/start_scan &lt;target URL&gt;</code>
        <br />
      </td>
      <td>
        <img src="https://raw.githubusercontent.com/DTai261/Acunetix_tele_bot/main/attachments/start_scan_2.png" alt="6"/>
        <br />
      </td>
    </tr>
  </table>

### `/get_processing_targets`
  <table>
    <tr>
        <td>
          <img src="https://raw.githubusercontent.com/DTai261/Acunetix_tele_bot/main/attachments/get_processing_targets_1.png" alt="7"/>
          <br>
          <code>/get_processing_targets</code>: get processing targets
          <br />
        </td>
      </tr>
  </table>

### `/set_targets`
Set number of concurrent targets. If the current number of targets is larger than the set number, the bot will do nothing but wait for one of the targets end, or force to end by the scan time in config file. 
  <table>
    <tr>
        <td>
          <img src="https://raw.githubusercontent.com/DTai261/Acunetix_tele_bot/main/attachments/set_target_1.png" alt="8"/>
          <br>
          <code>/set_target &lt;int&gt;</code>
          <br />
        </td>
      </tr>
  </table>

### `/stop_scan_acunetix`
Stop scan by it id. You can get the scan id of the target by using command <code>/get_processing_targets</code>.
  <table>
    <tr>
        <td>
          <img src="https://raw.githubusercontent.com/DTai261/Acunetix_tele_bot/main/attachments/stop_scan_acunetix_1.png" alt="8"/>
          <br>
          <code>/set_target</code>: &lt;scan_id&gt;
          <br />
        </td>
      </tr>
  </table>

### `Auto notification when new vuln detected`
The bot will auto check for new vulns found by Acunetix of all targets every 1 min, if there are new vuln have severity from medium-critical it will sent user the vuln detail. 
<br><img src="https://raw.githubusercontent.com/DTai261/Acunetix_tele_bot/main/attachments/auto_noti_1.png" alt="9"/>

### `/stop_vuln`
To stop receive a specific vuln you can use command <code>/stop_vuln vuln_id</code>. You can get the vuln id at the end of the vuln detail message or use command <code>/vuln_type int</code> or command <code>/get_list_vulns int</code>
  <table>
    <tr>
        <td>
          <img src="https://raw.githubusercontent.com/DTai261/Acunetix_tele_bot/main/attachments/stop_vuln_1.png" alt="10"/>
          <br>
          <code>/stop_vuln &lt;vuln_id&gt;</code>
          <br />
        </td>
      </tr>
  </table>

### `/vuln_type`
Find vuln type by severity (1-4: 4 is critical, 1 is info) on all targets. Eg: search for high severity vulns:
  <table>
    <tr>
        <td>
          <img src="https://raw.githubusercontent.com/DTai261/Acunetix_tele_bot/main/attachments/vuln_type_1.png" alt="11"/>
          <br>
          <code>/vuln_type &lt;int(1-4)&gt;</code>
          <br />
        </td>
      </tr>
  </table>

### `/search_by_vuln_type`
Search all the targets that have specific vulnerabilities by vuln type id.
  <table>
    <tr>
        <td>
          <img src="https://raw.githubusercontent.com/DTai261/Acunetix_tele_bot/main/attachments/search_by_vuln_type_1.png" alt="12"/>
          <br>
          <code>/search_by_vuln_type &lt;vuln_type_id&gt;</code>
          <br />
        </td>
      </tr>
  </table>

### `/get_list_vulns`
Or you can search for specific severity for specific target URL.
  <table>
    <tr>
        <td>
          <img src="https://raw.githubusercontent.com/DTai261/Acunetix_tele_bot/main/attachments/get_list_vulns_1.png" alt="13"/>
          <br>
          <code>/get_list_vulns &lt;severity&gt; &lt;target URL&gt;</code>
          <br />
        </td>
        <td>
          <img src="https://raw.githubusercontent.com/DTai261/Acunetix_tele_bot/main/attachments/get_list_vulns_2.png" alt="14"/>
          <br>
          <br />
        </td>
      </tr>
  </table>

### `/vuln_detail`
Get the vuln detail by id: http request, highlighted, references, ...
  <table>
    <tr>
        <td>
          <img src="https://raw.githubusercontent.com/DTai261/Acunetix_tele_bot/main/attachments/vuln_detail_1.png" alt="15"/>
          <br>
          <code>/vuln_detail &lt;vuln_id&gt;</code>
          <br />
        </td>
      </tr>
  </table>

### `Another command:`
  <table>
    <tr>
        <td>
          <img src="https://raw.githubusercontent.com/DTai261/Acunetix_tele_bot/main/attachments/ram_1.png" alt="16"/>
          <br>
          <code>/ram</code>
          <br />
        </td>
        <td>
          <img src="https://raw.githubusercontent.com/DTai261/Acunetix_tele_bot/main/attachments/note_1.png" alt="17"/>
          <br>
          <code>/note</code> / <code>/read_note</code>
          <br />
        </td>
      </tr>
      <tr>
        <td>
        <img src="https://raw.githubusercontent.com/DTai261/Acunetix_tele_bot/main/attachments/auto_abort_1.png" alt="18">
          <br>
          <code>/auto_abort_scan_false</code> / <code>/auto_abort_scan_true</code>
        </td>
      </tr>
  </table>

### Note
###### 1:
- because of the conflict to the httpx of python I have to change the name of the binary file from httpx to httpxx. You can modify at this [line](https://github.com/DTai261/Acunetix_tele_bot/blob/main/AcuScan.py#L158).

###### 2: 
- Currently scan nuclei not available yet because I did some stupid stuff with it :v I may update it in the future.