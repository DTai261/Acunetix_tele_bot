ACUNETIX_API_KEY="xxxxxxxxxxxxxxxxxxx"
HOST= "https://localhost:13443"
#Number of target scan at the same time
NUMBER_OF_TARGETS_SIMULTANEOUSLY = 3
API_SERVER = True

#scan profile here: 
SCAN_PROFILE = {
    "name": "AcuScan Auto Profile",
    "custom": "true",
    "checks": [
        "wvs/RPA/InsecureTransition.js",
        "wvs/httpdata/mixed_content_over_https.js",
        "wvs/RPA/Cookie_On_Parent_Domain.js",
        "wvs/RPA/Cookie_Without_HttpOnly.js",
        "wvs/RPA/Cookie_Without_Secure.js",
        "wvs/RPA/Cookie_Validator.js",
        "wvs/RPA/SRI_Not_Implemented.js",
        "wvs/Scripts/PerServer/Reverse_Proxy_Bypass.script",
        "wvs/target/RevProxy_Detection.js",
        "wvs/Crawler/HTTPS_insecure_maxTLS.js",
        "wvs/Scripts/PerFile/Javascript_Libraries_Audit.script",
        "wvs/httpdata/javascript_library_audit_external.js",
        "wvs/httpdata/permissions_policy.js",
        "wvs/httpdata/CSP_not_implemented.js",
        "wvs/httpdata/content_security_policy.js",
        "wvs/httpdata/rails_accept_file_content_disclosure.js",
        "wvs/httpdata/X_Frame_Options_not_implemented.js",
        "wvs/httpdata/iframe_sandbox.js",
        "wvs/Scripts/PerServer/SSL_Audit.script",
        "wvs/target/ssltest",
        "wvs/httpdata/HSTS_not_implemented.js",
        "ovas/",
    ],
}

SCAN_PROFILE_ID = 'xxxxxxxxxxxxxxxxxxxxxxxxx'
OUT_SCOPE_VULN_ACUNETIX = [
    '26f9af3b-acf6-f3e4-0fdc-567ac9e03527',
    'bca221d1-8581-3375-4097-66b0048ed088',
    '3f6a8a0e-07f2-af81-54ff-61020299caeb',
    '34a6c791-c497-27d5-7272-6a968e9fdccb', # HTTP Strict Transport Security (HSTS) Policy Not Enabled
    '391f39d7-6805-cd0c-44ec-df4bf71273eb', # Host header attack
    '84fd0f24-a88f-09cf-97eb-67959deb26d4', # Vulnerable JavaScript libraries
    'dc80dd1d-735b-4ba7-b279-589743eeba6e', # WordPress Deserialization of Untrusted Data Vulnerability
    '029afcbb-3ec2-be3c-5cc3-29f5cfe016f4', # SSL Certificate Is About To Expire
    '253317f4-6382-e8f5-acd2-b69f488adc11', # WordPress 6.0.x Multiple Vulnerabilities
    '59ec3cbe-d67f-6a74-6aa1-f449d224ab71' # Vulnerable package dependencies
]
# Time to scan acunetix (hours) after this time the tool will auto stop the target unless user config not auto abort on that target
SCAN_TIME = 24

NOTIFICATION = False

#telegram bot api key:
TELEGRAM_API_KEY = 'xxxxxxxxxxxxxxxx'

#id of user that allowed to send command
ALLOWED_USER_ID = 000000000

OUT_SCOPE_VULN_NUCLEI = ['CVE-xxxx-xxxx']

API_PORT = 5000
# If TOKEN_EXPIRATION is None, the token will not expire
TOKEN_EXPIRATION = 3600  # 1 hour

#SECRET_KEY for the JWT
SECRET_KEY = 'YOUR_SECRET_KEY'  # Use a secure, random secret key for JWT
