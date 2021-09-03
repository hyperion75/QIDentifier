from bs4 import BeautifulSoup
import keyring
import requests as requests
import re
import base64
import enlighten
import math
import warnings

global MANAGER

# scrubs HTML tags from KB output
TAG_RE = re.compile(r'<[^>]+>')
warnings.filterwarnings("ignore", message='Unverified HTTPS request is being made')


def remove_tags(text):
    return TAG_RE.sub('', text)


def base64encoder():
    username = keyring.get_password("QIDentifier.USER", "QIDer")
    password = keyring.get_password("QIDentifier.PASS", "QIDer")
    message = username + ":" + password
    message_bytes = message.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    base64_encoded = base64_bytes.decode('ascii')
    return base64_encoded


def geturl():
    pod = keyring.get_password("QIDentifier.POD", "QIDer")
    if pod == '1':
        url = 'https://qualysapi.qualys.com/api/2.0/fo/knowledge_base/vuln/'
    elif pod == '2':
        url = 'https://qualysapi.qg2.apps.qualys.com/api/2.0/fo/knowledge_base/vuln/'
    elif pod == '3':
        url = 'https://qualysapi.qg3.apps.qualys.com/api/2.0/fo/knowledge_base/vuln/'
    return url


# Connects to Qualys API and runs Knowledgebase query for provided QID.
# Credentials / POD can be changed from UI and are stored in system keychain.
def pullkb(qid):
    authstring = "Basic " + base64encoder()
    payload = {'action': 'list',
               'details': 'All',
               'ids': qid}
    headers = {
        'X-Requested-With': 'QualysPostman',
        'Authorization': authstring,
    }

    response = requests.request("POST", geturl(), headers=headers, data=payload, stream=True)
    kb_querystatus = response.status_code
    print(kb_querystatus)

    # monitor API download live in console. tracks data being imported from API to parsefile.kb
    parsefile = 'parsefile.kb'
    MANAGER = enlighten.get_manager()

    assert response.status_code == 200, response.status_code
    dlen = int(response.headers.get('Content-Length', 0)) or None

    with MANAGER.counter(color='green', total=dlen and math.ceil(dlen / 2 ** 20), unit='MiB', leave=False) as ctr, \
            open(parsefile, 'wb', buffering=2 ** 24) as f:
        for chunk in response.iter_content(chunk_size=2 ** 20):
            print(chunk[-16:].hex().upper())
            f.write(chunk)
            ctr.update()

    # Pull parsed KB info from parsefile.kb and convert to variables for UI display
    soup = BeautifulSoup(open('parsefile.kb'), 'html.parser')
    attrlist = []
    kb_attributes = ['vuln_type', 'severity_level', 'title', 'category', 'last_service_modification_datetime',
                     'published_datetime', 'patchable', 'product', 'vendor', 'vendor_reference', 'diagnosis',
                     'consequence', 'solution', 'remote']
    for attr in kb_attributes:
        x = soup.find(attr)
        if x != None:
            attrlist.append(x.get_text())
        elif x == None:
            attrlist.append(x)

    cvelist = []
    kb_cve_list_pre = soup.find_all('cve')
    for x in kb_cve_list_pre:
        cvelist.append(x.get_text())
    kb_cve_list = '\n'.join(cvelist)

    threatlist = []
    kb_threat_intel_pre = soup.find_all('threat_intel')
    for x in kb_threat_intel_pre:
        threatlist.append('* ' + x.get_text())
    kb_threat_intel = '\n'.join(threatlist)

    authlist = []
    kb_auth_type_pre = soup.find_all('auth_type')
    for x in kb_auth_type_pre:
        authlist.append('* ' + x.get_text())
    kb_auth_type = '\n'.join(authlist)

    list_main = []
    list_threat = []
    list_solution = []
    list_cve = []

    list_main.append("Title: " + attrlist[2])
    list_main.append("Vulnerability Type: " + attrlist[0] + " (Level " + attrlist[1] + ")")
    list_main.append("Category: " + attrlist[3])
    list_main.append("Last Modified: " + attrlist[4])
    list_main.append("Published: " + attrlist[5])
    if attrlist[6] == '1':
        list_main.append("Patchable: Yes")
    else:
        list_main.append("Patchable: No")
    list_main.append("Vendor: " + attrlist[8].capitalize())
    list_main.append("Product: " + attrlist[7].capitalize())
    if isinstance(attrlist[9], str):
        list_main.append("Vendor Reference: " + remove_tags(attrlist[9]))
    list_cve.append(kb_cve_list)
    if isinstance(attrlist[10], str):
        list_threat.append(remove_tags(attrlist[10]))
    if isinstance(attrlist[11], str):
        list_threat.append("Consequence: " + remove_tags(attrlist[11]))
    if isinstance(attrlist[12], str):
        list_solution.append(remove_tags(attrlist[12]))
        solutionlinks = BeautifulSoup(attrlist[12], 'lxml')
        for x in solutionlinks.find_all('a', href=True):
            list_solution.append('* ' + x['href'])
    list_threat.append("Threat Identifiers: " + '\n' + kb_threat_intel)
    if attrlist[13] == '1':
        list_main.append("Authentication Not Required")
    else:
        list_main.append("Authentication Required")
        list_main.append("Supported Authentication: " + '\n' + kb_auth_type)

    main = '\n\n'.join(list_main)
    threat = '\n\n'.join(list_threat)
    solution = '\n\n'.join(list_solution)
    cve = '\n\n'.join(list_cve)
    return (main, threat, solution, cve)
