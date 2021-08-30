import PullSigs
import KBPull
import vspull
from tkinter import *
import base64
import keyring
from tkinter import ttk

# create root window
root = Tk()
root.eval('tk::PlaceWindow . center')
root.title("QIDentifier")
root.geometry('1280x720')

#Required for checkbox functionality
exclude_kb_on = BooleanVar()

def closewindow(x):
    x.destroy()

def set_vs_version(ver):
    version = ver.get()
    keyring.set_password("QIDentifier.VS_VER", "VS", version)
    vsTitle.config(text="VulnSigs Sandbox: " + version)

#Started work on a button to switch between QID/CVE search methods
"""def searchmethod(x):
    global sm
    if x == 0:
        switchbuttonx.config(text="CVE:")
        sm = 1
        print("Searchmethod set to " + str(sm))
    elif x == 1:
        switchbuttonx.config(text="QID:")
        sm = 0
        print("Searchmethod set to " + str(sm))
    #searchmethod = Button(topframe, text="QID:", bg='#FFFFFF', font=arialheader, command=searchmethod())"""

# 2 functions - Set the POD in keychain, then set the API login string in keychain.

def storecredentials(username, password, pod):
    s_pod = pod.get()
    username = username.get()
    password = password.get()
    print(s_pod)
    print(username)
    print(password)
    if s_pod == ' US POD 1':
        platform = '1'
    elif s_pod == ' US POD 2':
        platform = '2'
    elif s_pod == ' US POD 3':
        platform = '3'
    keyring.set_password("QIDentifier.POD", "QIDer", platform)
    keyring.set_password("QIDentifier.USER", "QIDer", username)
    keyring.set_password("QIDentifier.PASS", "QIDer", password)

# Changed behavior of User/Pass/POD variable storage for added flexibility with new features.
# Encoding functionality moved to KBPull.py.
"""def buildbase64(username, password, pod):
    s_pod = pod.get()
    if s_pod == ' US POD 1':
        url = 'https://qualysapi.qualys.com/api/2.0/fo/knowledge_base/vuln/'
    elif s_pod == ' US POD 2':
        url = 'https://qualysapi.qg2.apps.qualys.com/api/2.0/fo/knowledge_base/vuln/'
    elif s_pod == ' US POD 3':
        url = 'https://qualysapi.qg3.apps.qualys.com/api/2.0/fo/knowledge_base/vuln/'
    keyring.set_password("QIDentifier.API_URL", "API", url)


    message = username.get() + ":" + password.get()
    message_bytes = message.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    base64_encode = base64_bytes.decode('ascii')
    keyring.set_password("QIDentifier", "API", base64_encode)"""

#Popup window for POD Selection / API Login
def loginpopup():
    loginwindow = Toplevel(root)
    root.eval(f'tk::PlaceWindow {str(loginwindow)} center')
    loginwindow.title("Qualys API Credentials")
    loginwindow.geometry("400x250")

    instruction_label = Label(loginwindow, text="Please select a POD and enter your API credentials:")
    instruction_label.pack()

    pod_label = Label(loginwindow, text="POD:")
    pod_label.pack()
    pod = StringVar()
    pod_entry = ttk.Combobox(loginwindow, width = 27, textvariable = pod)
    pod_entry['values'] = (' US POD 1',
                           ' US POD 2',
                           ' US POD 3')
    pod_entry.pack()

    username_label = Label(loginwindow, text="Username:")
    username_label.pack()
    username = StringVar()
    username_entry = Entry(loginwindow, textvariable=username)
    username_entry.pack()

    password_label = Label(loginwindow, text="Password:")
    password_label.pack()
    password = StringVar()
    password_entry = Entry(loginwindow, show='*', textvariable=password)
    password_entry.pack()

    login_confirm = Button(loginwindow, text="Set Credentials", width=12, height=1,
                           command=lambda : storecredentials(username, password, pod))
    login_confirm.pack()
    okbutton = Button(loginwindow, text="OK", width=10, height=1, command=lambda : closewindow(loginwindow))
    okbutton.pack()

#Popup window for VULNSIGS version selection
def vsupdatepopup():
    vsuwindow = Toplevel(root)
    root.eval(f'tk::PlaceWindow {str(vsuwindow)} center')
    vsuwindow.title("VulnSigs Version Selector")
    vsuwindow.geometry("250x100")

    instruction_label = Label(vsuwindow, text="Select a VulnSigs Version:")
    instruction_label.pack()

    versiontuple = tuple(vspull.vspull())
    ver = StringVar()
    ver_entry = ttk.Combobox(vsuwindow, width = 27, textvariable = ver)
    ver_entry['values'] = versiontuple
    ver_entry.pack()

    vs_confirm = Button(vsuwindow, text="Set Version", width=12, height=1, command=lambda : set_vs_version(ver))
    vs_confirm.pack()

    okbutton = Button(vsuwindow, text="OK", width=10, height=1, command=lambda : closewindow(vsuwindow))
    okbutton.pack()

#Executed when user clicks the "retrieve information" button. This does all the work.
def pullinfo():
    qid = qidInput.get()
    vs_output.delete(1.0,END)
    kb_output.delete(1.0,END)
    # Display Sandbox Information
    vs_display = PullSigs.pullsigs(qid)
    # Display KB Information (if checkbox unchecked)
    if exclude_kb_on.get()==0:
        kb_display = KBPull.pullkb(qid)
        kb_output.insert(END, kb_display)
    vs_output.insert(END, vs_display)

#Everything below this is UI position related
#Top, Middle, Bottom, Footer frame definitions
frame = Frame(root)
frame.pack()
topframe = Frame(root, relief=RAISED, borderwidth=2)
topframe.pack(side=TOP, fill='x')
midframe = Frame(root)
midframe.pack(side=TOP, fill='x', ipadx=30)
footerframe = Frame(root)
footerframe.pack(side=BOTTOM, fill='x')
bottomframe = Frame(root)
bottomframe.pack(side=BOTTOM, expand=True, fill=BOTH)

#fonts
arialheader = ("Arial", 16, "bold")
arialbold = ("Arial", 12, "bold")
arial = ("Arial", 12)

#UI Elements
#sm = 0
switchbuttonx = Label(topframe, text="QID:", bg='#FFFFFF', font=arialheader)
switchbuttonx.pack(side=LEFT)

qidInput = Entry(topframe, width=12)
qidInput.pack(side=LEFT)

btn_retrieve = Button(topframe, text="Go",
             fg="orange red", command=pullinfo, font=arial)
btn_retrieve.pack(side=LEFT)

exclude_kb = Checkbutton(topframe, text="Exclude KB Info", font=arial, variable=exclude_kb_on)
exclude_kb.pack(side=RIGHT)

# vsTitle is set to global so that it's updated automatically when you change VULNSIGS version.
global vsTitle
if keyring.get_password("QIDentifier.VS_VER", "VS") == None:
    vsText = "VulnSigs Sandbox: VERSION NOT CONFIGURED"
elif keyring.get_password("QIDentifier.VS_VER", "VS") != "":
    vsText = "VulnSigs Sandbox: " + keyring.get_password("QIDentifier.VS_VER", "VS")

vsTitle = Label(midframe, text=vsText, font=arialbold)
vsTitle.pack(side=LEFT)

kbTitle = Label(midframe, text="Qualys Knowledgebase", font=arialbold)
kbTitle.pack(side=RIGHT)

vs_output = Text(bottomframe, bg="alice blue", font=arial)
vs_output.pack(side=LEFT, expand=True, fill=BOTH)

kb_output = Text(bottomframe, bg="gainsboro", font=arial)
kb_output.pack(side=RIGHT, expand=True, fill=BOTH)
kb_output.insert(END, "Pulling KB information may take some time.\n\nIf you don't need it, check the box above.")

config_acct = Button(footerframe, text="Configure API Account", command=lambda : loginpopup())
config_acct.pack(side=RIGHT)

config_vs_ver = Button(footerframe, text="Set VULNSIGS Version", command=lambda : vsupdatepopup())
config_vs_ver.pack(side=LEFT)

# Execute Tkinter
root.mainloop()

