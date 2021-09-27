from tkinter import *
from tkinter import ttk
import requests
from bs4 import BeautifulSoup
import keyring
import base64
import os
import re
import warnings

os.chdir(os.path.dirname(os.path.abspath(__file__)))
TAG_RE = re.compile(r'<[^>]+>')
warnings.filterwarnings("ignore", message='Unverified HTTPS request is being made')

# Useful for working directory troubleshooting:
"""cwd = os.getcwd()
print("Current working directory: {0}".format(cwd))
print("Current script directory:" + os.path.realpath(__file__))
files = [f for f in os.listdir('.') if os.path.isfile(f)]
for f in files:
    print(f)"""

# create root window
root = Tk()
root.title("QIDentifier")
root.geometry('1280x720')


def centerwindow(win):
    win.update_idletasks()
    width = win.winfo_width()
    frm_width = win.winfo_rootx() - win.winfo_x()
    win_width = width + 2 * frm_width
    height = win.winfo_height()
    titlebar_height = win.winfo_rooty() - win.winfo_y()
    win_height = height + titlebar_height + frm_width
    x = win.winfo_screenwidth() // 2 - win_width // 2
    y = win.winfo_screenheight() // 2 - win_height // 2
    win.geometry('{}x{}+{}+{}'.format(width, height, x, y))
    win.deiconify()


centerwindow(root)

root.tk.call("source", "sun-valley.tcl")
root.tk.call("set_theme", "light")

# Required for checkbox functionality
exclude_kb_on = BooleanVar()


def closewindow(x):
    x.destroy()


def set_vs_version(ver):
    version = ver.get()
    keyring.set_password("QIDentifier.VS_VER", "VS", version)
    print('INFO: Setting VulnSigs version.')
    vsTitle.config(text="VulnSigs Sandbox: " + version)


def list_vs_versions():
    url = "https://10.80.8.21/"
    headers = {
        'Connection': 'keep-alive',
        'Accept': '*/*',
        'Accept-Encoding': 'gzip,deflate,br',
        'Accept-Language': 'en-US,en;q=0.9'
    }
    response = requests.request("GET", url, headers=headers, verify=False)
    if response.status_code == 200:
        print('INFO: Successfully connected to VulnSigs Sandbox (https://10.80.8.21/)')
    else:
        print('ERROR: Could not connect to VulnSigs Sandbox (https://10.80.8.21/)')

    soup = BeautifulSoup(response.content, 'html.parser')

    parsed = list(soup.find_all('option'))
    versionlist = []
    for x in parsed:
        versionlist.append(x.get_text())
    return versionlist


# Started work on a button to switch between QID/CVE search methods
def searchmethod(x):
    global sm
    if x == 0:
        switchbuttonx.config(text="CVE")
        sm = 1
        print("INFO: SearchMethod set to CVE.")
    elif x == 1:
        switchbuttonx.config(text="QID")
        sm = 0
        print("INFO: SearchMethod set to QID.")


# 2 functions - Set the POD in keychain, then set the API login string in keychain.

def storecredentials(username, password):
    username = username.get()
    password = password.get()
    keyring.set_password("QIDentifier.USER", "QIDer", username)
    keyring.set_password("QIDentifier.PASS", "QIDer", password)
    print('INFO: Successfully stored credentials in keychain.')


# Popup window for POD Selection / API Login
def settingspane():
    settings = Toplevel(root)
    settings.title("QIDentifier Settings")
    settings.geometry("750x285")
    settings.resizable(False, False)
    centerwindow(settings)

    # settings UI positioning
    credentialframe = ttk.LabelFrame(settings, text="Corp Credentials", padding=(20, 10))
    credentialframe.grid(row=1, column=1, padx=(20, 10), pady=(20, 10), sticky="nsew", rowspan=2)
    vulnsigsframe = ttk.LabelFrame(settings, text="VULNSIGS Settings", padding=(20, 10))
    vulnsigsframe.grid(row=1, column=2, padx=(20, 10), pady=(20, 10), sticky="n")

    # settings UI elements
    closebutton = ttk.Button(settings, text="Done", width=10, command=lambda: closewindow(settings))
    closebutton.grid(row=2, column=2, padx=(20, 10), pady=(20, 10), sticky="n")

    # login settings

    username_label = ttk.Label(credentialframe, text="Username:")
    username_label.grid(row=0, column=0, pady=15)
    username = StringVar()
    username_entry = ttk.Entry(credentialframe, width=15, textvariable=username)
    username_entry.grid(row=0, column=1)

    password_label = ttk.Label(credentialframe, text="Password:")
    password_label.grid(row=1, column=0, pady=15)
    password = StringVar()
    password_entry = ttk.Entry(credentialframe, show='*', width=15, textvariable=password)
    password_entry.grid(row=1, column=1)

    login_confirm = ttk.Button(credentialframe, text="Set Credentials", width=12,
                               command=lambda: storecredentials(username, password))
    login_confirm.grid(row=3, column=1, pady=15)

    instruction_label_vs = ttk.Label(vulnsigsframe, text="VULNSIGS Version:")
    instruction_label_vs.grid(row=0, column=0, pady=15, padx=10)

    versiontuple = tuple(list_vs_versions())
    ver = StringVar()
    ver_entry = ttk.Combobox(vulnsigsframe, width=20, textvariable=ver)
    ver_entry['values'] = versiontuple
    ver_entry.grid(row=0, column=1)

    vs_confirm = ttk.Button(vulnsigsframe, text="Set Version", width=12, command=lambda: set_vs_version(ver))
    vs_confirm.grid(row=2, column=1, pady=15)


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


def pullsigs(qid):
    vulnVersion = keyring.get_password("QIDentifier.VS_VER", "VS")
    url = "https://10.80.8.21/vuln/search"
    payload = 'qid=' + str(qid) + '&vulnVersion=' + str(vulnVersion)
    headers = {
        'Connection': 'keep-alive',
        'Accept': '*/*',
        'X-Requested-With': 'XMLHttpRequest',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Accept-Encoding': 'gzip,deflate,br',
        'Accept-Language': 'en-US,en;q=0.9'
    }
    response = requests.request("POST", url, headers=headers, data=payload, verify=False)
    if response.status_code == 200:
        print('INFO: Successfully connected to VulnSigs Sandbox (https://10.80.8.21/)')
    else:
        print('ERROR: Could not connect to VulnSigs Sandbox (https://10.80.8.21/)')

    soup = BeautifulSoup(response.content, 'html.parser')

    parsed = list(soup.find_all('div', class_='panel-body'))
    list_sig = []
    list_func = []
    substring1 = "qlua_func"
    substring2 = "qlua_dfunc"
    for x in parsed:
        # .find() doesn't support lists, I'll have to switch this around to use another method sometime.
        if str(x).find(substring1) != -1:
            list_func.append(x.get_text() + '\n' + "================================")
        elif str(x).find(substring2) != -1:
            list_func.append(x.get_text() + '\n' + "================================")
        else:
            list_sig.append(x.get_text() + '\n' + "================================")
    # sigs = '\n\n'.join(siglist)

    sigs = '\n\n'.join(list_sig)
    funcs = '\n\n'.join(list_func)

    return sigs, funcs


def pullqid(qid):
    auth = "Basic " + base64encoder()
    # print(auth)
    payload = {}
    headers = {
        'X-Requested-With': 'QualysPostman',
        'Authorization': auth,

    }

    response = requests.request("GET",
                                "https://vuln.intranet.qualys.com:8443/main/qualysedit.php?id=" + qid + "&lang=en",
                                headers=headers, data=payload, verify=False)
    if response.status_code == 200:
        print('INFO: Successfully connected to VulnOffice (https://vuln.intranet.qualys.com:8443)')
    else:
        print('ERROR: Could not connect to VulnOffice (https://vuln.intranet.qualys.com:8443). Verify your corp '
              'credentials are correct.')

    soup = BeautifulSoup(response.content, 'html.parser')

    # Main Tab Information
    list_main = []
    q_name = soup.find('input', {"name": "form[TITLE]"})
    if q_name['value'] != '':
        list_main.append("Title: " + q_name['value'])
    else:
        main = "The provided QID does not match Qualys records."
        detail = "The provided QID does not match Qualys records."
        ref = "The provided QID does not match Qualys records."
        print('ERROR: Unrecognized QID')
        return main, detail, ref

    q_vulntype_prep = soup.find('select', {"name": "form[CATEGORY]"})
    if q_vulntype_prep.has_attr('name'):
        q_vulntype = q_vulntype_prep.find("option", {'selected': True})
        if q_vulntype['value'] == 'Vuln':
            list_main.append("Vulnerability Type: Confirmed Vulnerability")
        elif q_vulntype['value'] == 'Practice':
            list_main.append("Vulnerability Type: Potential Vulnerability")
        else:
            print('ERROR: Unrecognized Vuln Type - ' + q_vulntype)
            list_main.append("Vulnerability Type: Unknown Vuln Type")

    q_sev_prep = soup.find('select', {"name": "form[SEVERITY]"})
    if q_sev_prep.has_attr('name'):
        q_sev = q_sev_prep.find("option", {'selected': True})
        if q_sev is not None:
            list_main.append("Severity: Level " + q_sev['value'])

    q_cvss3 = soup.find("input", {"name": "form[BASESCORE_V3]"})
    if q_cvss3 is not None:
        list_main.append("CVSS3: " + q_cvss3['value'])

    q_pubstatus_prep = soup.find('select', {"name": "form[PUBLISHED]"})
    if q_pubstatus_prep.has_attr('name'):
        q_pubstatus = q_pubstatus_prep.find("option", {'selected': True})
        q_pubdate = soup.find('input', {"name": "form[OLD_DATE_RELEASED]"})
        list_main.append("Published: " + q_pubstatus['value'] + " - " + q_pubdate['value'])

    q_vendor = soup.find("input", {"name": "form[VENDOR][0]"})
    if q_vendor.has_attr('value'):
        list_main.append("Vendor: " + q_vendor['value'].capitalize())

    q_product = soup.find("input", {"name": "form[PRODUCT][0]"})
    if q_product.has_attr('value'):
        list_main.append("Product: " + q_product['value'].capitalize())

    q_auth = ['Supported Authentication:']
    q_auth_prep = soup.find_all('input', {'id': re.compile('prop_auth_flag.*')})
    for x in q_auth_prep:
        if x.has_attr('checked'):
            if x['checked'] == 'true':
                if x['name'] == 'form[PROPERTIES_FLAG][atc]':
                    q_auth.append('* Apache Tomcat')
                if x['name'] == 'form[PROPERTIES_FLAG][mdb]':
                    q_auth.append('* MongoDB')
                if x['name'] == 'form[PROPERTIES_FLAG][pan]':
                    q_auth.append('* PANOS')
                if x['name'] == 'form[PROPERTIES_FLAG][wlg]':
                    q_auth.append('* WebLogic')
                if x['name'] == 'form[PROPERTIES_FLAG][win]':
                    q_auth.append('* Windows')
                if x['name'] == 'form[PROPERTIES_FLAG][unx]':
                    q_auth.append('* Unix')
                if x['name'] == 'form[PROPERTIES_FLAG][orc]':
                    q_auth.append('* Oracle')
                if x['name'] == 'form[PROPERTIES_FLAG][snmp]':
                    q_auth.append('* SNMP')
                if x['name'] == 'form[PROPERTIES_FLAG][db2]':
                    q_auth.append('* DB2')
                if x['name'] == 'form[PROPERTIES_FLAG][wbs]':
                    q_auth.append('* WebScan')
                if x['name'] == 'form[PROPERTIES_FLAG][vmw]':
                    q_auth.append('* VMware')
                if x['name'] == 'form[PROPERTIES_FLAG][mss]':
                    q_auth.append('* MS SQL')
                if x['name'] == 'form[PROPERTIES_FLAG][noa]':
                    q_auth.append('* No Auth')
                if x['name'] == 'form[PROPERTIES_FLAG][hba]':
                    q_auth.append('* HTTP Basic')
                if x['name'] == 'form[PROPERTIES_FLAG][syb]':
                    q_auth.append('* Sybase')
                if x['name'] == 'form[PROPERTIES_FLAG][mys]':
                    q_auth.append('* My SQL')
                if x['name'] == 'form[PROPERTIES_FLAG][pgs]':
                    q_auth.append('* PostgreSQL')
                if x['name'] == 'form[PROPERTIES_FLAG][frm]':
                    q_auth.append('* Form Auth')

    list_main.append('\n'.join(q_auth))

    q_qprod = ['Supported Products:']
    q_qprod_prep = soup.find_all('input', {'name': 'form[QUALYS_PRODUCT][]'})
    for x in q_qprod_prep:
        if x.has_attr('checked'):
            if x['value'] == '1':
                q_qprod.append('* Vulnerability Management')
            if x['value'] == '4':
                q_qprod.append('* Web Application Scanning')
            if x['value'] == '5':
                q_qprod.append('* Malware Detection')
            if x['value'] == '6':
                q_qprod.append('* Web Application Firewall')
            if x['value'] == '9':
                q_qprod.append('* API Security')
            if x['value'] == '10':
                q_qprod.append('* Secure Enterprise Mobility - iOS')
            if x['value'] == '11':
                q_qprod.append('* Secure Enterprise Mobility - Android')
            if x['value'] == '2':
                q_qprod.append('* Cloud Agent - Windows')
            if x['value'] == '3':
                q_qprod.append('* Cloud Agent - Linux')
            if x['value'] == '8':
                q_qprod.append('* Cloud Agent - AIX')
            if x['value'] == '7':
                q_qprod.append('* Cloud Agent - Mac')
            if x['value'] == '12':
                q_qprod.append('* Cloud Agent - BSD')
            if x['value'] == '14':
                q_qprod.append('* Cloud Agent - Solaris')

    list_main.append('\n'.join(q_qprod))

    # Detail Tab Information
    list_detail = []
    q_diagnosis = soup.find('textarea', {"name": "form[DESCRIPTION]"})
    if q_diagnosis.get_text() != "":
        list_detail.append(remove_tags('Diagnosis:' + '\n' + q_diagnosis.get_text()))

    q_consequence = soup.find('textarea', {"name": "form[CONSEQUENCE]"})
    if q_consequence.get_text() != "":
        list_detail.append(remove_tags('Consequence:' + '\n' + q_consequence.get_text()))

    q_solution = soup.find('textarea', {"name": "form[SOLUTION]"})
    if q_solution.get_text() != "":
        list_detail.append(remove_tags('Solution:' + '\n' + q_solution.get_text()))

    q_tid = ['Threat Identifiers:']
    q_tid_prep = soup.find_all('input', {'id': re.compile('threat_intel_id.*')})
    for x in q_tid_prep:
        if x.has_attr('checked'):
            if x['checked'] == '':
                if x['value'] == '12':
                    q_tid.append('* Predicted High Risk')
                if x['value'] == '11':
                    q_tid.append('* Wormable')
                if x['value'] == '17':
                    q_tid.append('* Solorigate Sunburst')
                if x['value'] == '15':
                    q_tid.append('* Remote Code Execution')
                if x['value'] == '13':
                    q_tid.append('* Privilege Escalation')
                if x['value'] == '14':
                    q_tid.append('* Unauthenticated Exploitation')
                if x['value'] == '1':
                    q_tid.append('* Zero Day')
                if x['value'] == '2':
                    q_tid.append('* Exploit Public')
                if x['value'] == '3':
                    q_tid.append('* Active Attacks')
                if x['value'] == '4':
                    q_tid.append('* High Lateral Movement')
                if x['value'] == '5':
                    q_tid.append('* Easy Exploit')
                if x['value'] == '6':
                    q_tid.append('* High Data Loss')
                if x['value'] == '7':
                    q_tid.append('* Denial of Service')
                if x['value'] == '8':
                    q_tid.append('* No Patch')
                if x['value'] == '9':
                    q_tid.append('* Malware')
                if x['value'] == '10':
                    q_tid.append('* Exploit Kit')
                if x['value'] == '16':
                    q_tid.append('* Ransomware')

    if q_tid == ['Threat Identifiers:']:
        list_detail.append('No Threat Identifiers')
    else:
        list_detail.append('\n'.join(q_tid))

    # Reference Tab Information
    list_ref = []

    q_cve = ['CVE: ']
    q_cve_prep = soup.find('input', {"name": "form[CVEID]"})
    if q_cve_prep.has_attr('value'):
        if q_cve_prep['value'] != 'GENERIC-MAP-NOMATCH':
            q_cve.append(q_cve_prep['value'])
        else:
            q_cve.append('No CVE Assigned')

    list_ref.append('\n'.join(q_cve))

    q_vref = soup.find('input', {"name": "form[VENDORID]"})
    if q_vref.has_attr('value'):
        list_ref.append("Vendor Reference: " + '\n' + q_vref['value'].replace("|+", "\n").replace("|", ""))

    main = '\n\n'.join(list_main)
    detail = '\n\n'.join(list_detail)
    ref = '\n\n'.join(list_ref)
    return (main, detail, ref)


def pullcve(cve):
    auth = "Basic " + base64encoder()
    payload = 'search=' + cve + '&type=CVE&src=QUALYS&lang=en'
    headers = {
        'X-Requested-With': 'QualysPostman',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': auth,

    }

    response = requests.request("POST",
                                "https://vuln.intranet.qualys.com:8443/main/index.php",
                                headers=headers, data=payload, verify=False)
    if response.status_code == 200:
        print('INFO: Successfully connected to VulnOffice (https://vuln.intranet.qualys.com:8443)')
    else:
        print('ERROR: Could not connect to VulnOffice (https://vuln.intranet.qualys.com:8443). Verify your corp '
              'credentials are correct.')

    soup = BeautifulSoup(response.content, 'html.parser')

    cve_list = []
    acve1 = []
    acve2 = []
    acve_prep1 = soup.find_all('a', {"target": "_blank"})
    acve_prep2 = soup.find_all('a', href=True)
    for x in acve_prep1:
        acve1.append(x['href'].replace('translate.php?id=', ''))
    for x in acve_prep2:
        if x.get_text() != '':
            if x.get_text() != 'jp':
                acve2.append(x.get_text().replace('\xa0', ""))
    zipacve = zip(acve1, acve2)
    acve = dict(zipacve)
    cve_list.append('\n'.join("{} | {}".format(k, v) for k, v in acve.items()))

    main = ''.join(cve_list)
    detail = ''.join(cve_list)
    ref = ''.join(cve_list)
    return (main, detail, ref)


def pullinfo():
    qid = qidInput.get()

    # Clear old information from leftbook and rightbook
    vso_sigs.delete(1.0, END)
    kbo_main.delete(1.0, END)
    kbo_detail.delete(1.0, END)
    kbo_ref.delete(1.0, END)

    # Display KB Information (if checkbox unchecked)
    # pulls tab data to rightbook
    if sm == 0:
        if 'CVE' not in qid:
            if exclude_kb_on.get() == 0:
                main, detail, ref = pullqid(qid)
                kbo_main.insert(END, main)
                kbo_detail.insert(END, detail)
                kbo_ref.insert(END, ref)
        else:
            kbo_main.insert(END, "The provided QID does not match Qualys records.\n\nDid you remember to switch to CVE mode?")
            kbo_detail.insert(END, "The provided QID does not match Qualys records.\n\nDid you remember to switch to CVE mode?")
            kbo_ref.insert(END, "The provided QID does not match Qualys records.\n\nDid you remember to switch to CVE mode?")
            print('ERROR: Unrecognized QID (CVE Detected)')
    if sm == 1:
        main, detail, ref = pullcve(qid)
        kbo_main.insert(END, main)
        kbo_detail.insert(END, detail)
        kbo_ref.insert(END, ref)

    # pulls tab data to leftbook
    if sm == 0:
        sigs, funcs = pullsigs(qid)
        vso_sigs.insert(END, sigs)
        vso_funcs.insert(END, funcs)


# Everything below this is UI position related
# Top, Middle, Bottom, Footer frame definitions
frame = Frame(root)
frame.pack()
topframe = Frame(root)
topframe.pack(side=TOP, fill='x', pady=10)
midframe = Frame(root)
midframe.pack(side=TOP, fill='x', pady=2)
footerframe = Frame(root)
footerframe.pack(side=BOTTOM, fill='x')
bottomframe = Frame(root)
bottomframe.pack(side=BOTTOM, expand=True, fill=BOTH)

# fonts
arialheader = ("Arial", 16, "bold")
arialbold = ("Arial", 12, "bold")
arial = ("Arial", 12)

# UI Elements
label_search = ttk.Label(topframe, text="Search:", font=arialheader)
label_search.pack(side=LEFT, padx=5)
sm = 0
switchbuttonx = ttk.Button(topframe, text="QID", command=lambda: searchmethod(sm))
switchbuttonx.pack(side=LEFT)

qidInput = ttk.Entry(topframe, width=14)
qidInput.pack(side=LEFT)

btn_retrieve = ttk.Button(topframe, text="Go", command=pullinfo)
btn_retrieve.pack(side=LEFT, padx=15)

# vsTitle is set to global so that it's updated automatically when you change VULNSIGS version.
global vsTitle
if keyring.get_password("QIDentifier.VS_VER", "VS") == None:
    vsText = "VulnSigs Sandbox: VERSION NOT CONFIGURED"
elif keyring.get_password("QIDentifier.VS_VER", "VS") == '':
    vsText = "VulnSigs Sandbox: VERSION NOT CONFIGURED"
elif keyring.get_password("QIDentifier.VS_VER", "VS") != "":
    vsText = "VulnSigs Sandbox: " + keyring.get_password("QIDentifier.VS_VER", "VS")

vsTitle = ttk.Label(midframe, text=vsText, font=arialbold)
vsTitle.pack(side=LEFT, padx=5)

kbTitle = ttk.Label(midframe, text="Qualys Knowledgebase", font=arialbold)
kbTitle.pack(side=RIGHT, padx=5)

# define the VS Signatures Notebook
leftbook = ttk.Notebook(bottomframe)
leftbook.pack(side=LEFT, fill=BOTH, expand=True)

# VULNSIGS notebook, signatures page
lb_tab1 = ttk.Frame(leftbook)
for index in [0, 1]:
    lb_tab1.columnconfigure(index=index, weight=1)
    lb_tab1.rowconfigure(index=index, weight=1)
leftbook.add(lb_tab1, text="Signatures")

vso_sigs = Text(lb_tab1, font=arial, wrap=WORD)
vso_sigs.pack(expand=True, fill=BOTH)

# VULNSIGS notebook, functions page
lb_tab2 = ttk.Frame(leftbook)
leftbook.add(lb_tab2, text="Functions")
vso_funcs = Text(lb_tab2, font=arial, wrap=WORD)
vso_funcs.pack(expand=True, fill=BOTH)

# define KB Output Notebook
rightbook = ttk.Notebook(bottomframe)
rightbook.pack(side=LEFT, fill=BOTH, expand=True)

# KBO Notebook, main page
rb_tab1 = ttk.Frame(rightbook)
for index in [0, 1]:
    rb_tab1.columnconfigure(index=index, weight=1)
    rb_tab1.rowconfigure(index=index, weight=1)
rightbook.add(rb_tab1, text="General")

kbo_main = Text(rb_tab1, font=arial, wrap=WORD)
kbo_main.pack(expand=True, fill=BOTH)

# KBO Notebook, detail page
rb_tab2 = ttk.Frame(rightbook)
rightbook.add(rb_tab2, text="Detail")
kbo_detail = Text(rb_tab2, font=arial, wrap=WORD)
kbo_detail.pack(expand=True, fill=BOTH)

# KBO Notebook, CVE page
rb_tab4 = ttk.Frame(rightbook)
rightbook.add(rb_tab4, text="Reference")
kbo_ref = Text(rb_tab4, font=arial, wrap=WORD)
kbo_ref.pack(expand=True, fill=BOTH)

settings = ttk.Button(footerframe, text="Settings", command=lambda: settingspane())
settings.pack(side=RIGHT)

exclude_kb = ttk.Checkbutton(footerframe, text="Exclude KB Info", variable=exclude_kb_on, style="Switch.TCheckbutton")
exclude_kb.pack(side=RIGHT)

# Execute Tkinter
root.mainloop()
