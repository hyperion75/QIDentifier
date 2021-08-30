from bs4 import BeautifulSoup
import keyring
import requests as requests
import re
import base64

#scrubs HTML tags from KB output
TAG_RE = re.compile(r'<[^>]+>')
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
        print('DING!')
    return url

#Connects to Qualys API and runs Knowledgebase query for provided QID.
#Credentials / POD can be changed from UI and are stored in system keychain.
def pullkb(qid):
    authstring = "Basic " + base64encoder()
    payload = {'action': 'list',
               'details': 'All',
               'ids': qid}
    headers = {
        'X-Requested-With': 'QualysPostman',
        'Authorization': authstring,
    }

    response = requests.request("POST", geturl(), headers=headers, data=payload)
    kb_querystatus = response.status_code
    print(kb_querystatus)
    soup = BeautifulSoup(response.content, 'html.parser')

    # Pull parsed KB info and convert to variables for UI display
    attrlist = []
    kb_attributes = ['vuln_type', 'severity_level', 'title', 'category', 'last_service_modification_datetime',
                     'published_datetime', 'patchable', 'product', 'vendor', 'vendor_reference', 'diagnosis',
                     'consequence', 'solution', 'remote']
    for attr in kb_attributes:
        x = soup.find(attr)
        if x != "":
            attrlist.append(x.get_text())
        elif x == "":
            attrlist.append(x)

    cvelist = []
    kb_cve_list_pre = soup.find_all('cve')
    for x in kb_cve_list_pre:
        cvelist.append('* ' + x.get_text())
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

    print(attrlist)

    kblist = []
    kblist.append("Title: " + attrlist[2])
    kblist.append("Vulnerability Type: " + attrlist[0] + " (Level " + attrlist[1] + ")")
    kblist.append("Category: " + attrlist[3])
    kblist.append("Last Modified: " + attrlist[4])
    kblist.append("Published: " + attrlist[5])
    if attrlist[6] == '1':
        kblist.append("Patchable: Yes")
    else:
        kblist.append("Patchable: No")
    kblist.append("Vendor: " + attrlist[8].capitalize())
    kblist.append("Product: " + attrlist[7].capitalize())
    kblist.append("Vendor Reference: " + remove_tags(attrlist[9]))
    kblist.append("CVE List: " + '\n' + kb_cve_list)
    kblist.append("Diagnosis: " + remove_tags(attrlist[10]))
    kblist.append("Consequence: " + remove_tags(attrlist[11]))
    kblist.append("Solution: " + remove_tags(attrlist[12]))
    kblist.append("Threat Identifiers: " + '\n' + kb_threat_intel)
    if attrlist[13] == '1':
        kblist.append("Authentication Not Required")
    else:
        kblist.append("Authentication Required")
    kblist.append("Supported Authentication: " + '\n' + kb_auth_type)


    kb = '\n\n'.join(kblist)
    return kb
