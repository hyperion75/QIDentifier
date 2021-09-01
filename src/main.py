from tkinter import *
from tkinter import ttk
import keyring
import KBPull
import PullSigs
import vspull
import os
import sys

os.chdir(os.path.dirname(os.path.abspath(__file__)))

# Get the current working directory
cwd = os.getcwd()
# Print the current working directory
print("Current working directory: {0}".format(cwd))
print("Current script directory:" + os.path.realpath(__file__))

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
    vsTitle.config(text="VulnSigs Sandbox: " + version)


# Started work on a button to switch between QID/CVE search methods
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
    #searchmethod = ttk.Button(topframe, text="QID:", bg='#FFFFFF', font=arialheader, command=searchmethod())"""

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

# Popup window for POD Selection / API Login
def settingspane():
    settings = Toplevel(root)
    settings.title("QIDentifier Settings")
    settings.geometry("750x285")
    settings.resizable(False, False)
    centerwindow(settings)

    # settings UI positioning
    credentialframe = ttk.LabelFrame(settings, text="API Credentials", padding=(20,10))
    credentialframe.grid(row=1, column=1, padx=(20,10), pady=(20,10), sticky="nsew", rowspan=2)
    vulnsigsframe = ttk.LabelFrame(settings, text="VULNSIGS Settings", padding=(20,10))
    vulnsigsframe.grid(row=1, column=2, padx=(20,10), pady=(20,10), sticky="n")

    # settings UI elements
    closebutton = ttk.Button(settings, text="Done", width=10, command=lambda: closewindow(settings))
    closebutton.grid(row=2,column=2, padx=(20,10), pady=(20,10), sticky="n")

    # login settings
    pod_label = ttk.Label(credentialframe, text="POD:")
    pod_label.grid(row=0, column=0, pady=15)
    pod = StringVar()
    pod_entry = ttk.Combobox(credentialframe, width=15, textvariable=pod)
    pod_entry['values'] = (' US POD 1',
                           ' US POD 2',
                           ' US POD 3')
    pod_entry.grid(row=0, column=1)

    username_label = ttk.Label(credentialframe, text="Username:")
    username_label.grid(row=1, column=0, pady=15)
    username = StringVar()
    username_entry = ttk.Entry(credentialframe, width=15, textvariable=username)
    username_entry.grid(row=1, column=1)

    password_label = ttk.Label(credentialframe, text="Password:")
    password_label.grid(row=2, column=0, pady=15)
    password = StringVar()
    password_entry = ttk.Entry(credentialframe, show='*', width=15, textvariable=password)
    password_entry.grid(row=2, column=1)

    login_confirm = ttk.Button(credentialframe, text="Set Credentials", width=12,
                               command=lambda: storecredentials(username, password, pod))
    login_confirm.grid(row=3, column=1, pady=15)

    instruction_label_vs = ttk.Label(vulnsigsframe, text="VULNSIGS Version:")
    instruction_label_vs.grid(row=0, column=0, pady=15, padx=10)

    versiontuple = tuple(vspull.vspull())
    ver = StringVar()
    ver_entry = ttk.Combobox(vulnsigsframe, width=20, textvariable=ver)
    ver_entry['values'] = versiontuple
    ver_entry.grid(row=0, column=1)

    vs_confirm = ttk.Button(vulnsigsframe, text="Set Version", width=12, command=lambda: set_vs_version(ver))
    vs_confirm.grid(row=2, column=1, pady=15)

# Executed when user clicks the "retrieve information" button. This does all the work.
def pullinfo():
    qid = qidInput.get()

    #Clear old information from leftbook and rightbook
    vso_sigs.delete(1.0, END)
    kbo_main.delete(1.0, END)
    kbo_threat.delete(1.0, END)
    kbo_solution.delete(1.0, END)
    kbo_cve.delete(1.0, END)

    # Display KB Information (if checkbox unchecked)
    #pulls tab data to rightbook
    if exclude_kb_on.get() == 0:
        main, threat, solution, cve = KBPull.pullkb(qid)
        kbo_main.insert(END, main)
        kbo_threat.insert(END, threat)
        kbo_solution.insert(END, solution)
        kbo_cve.insert(END, cve)

    #pulls tab data to leftbook
    sigs, funcs = PullSigs.pullsigs(qid)
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
# sm = 0
switchbuttonx = ttk.Label(topframe, text="QID:", font=arialheader)
switchbuttonx.pack(side=LEFT, padx=5)

qidInput = ttk.Entry(topframe, width=12)
qidInput.pack(side=LEFT, padx=5)

btn_retrieve = ttk.Button(topframe, text="Go", command=pullinfo)
btn_retrieve.pack(side=LEFT)

exclude_kb = ttk.Checkbutton(topframe, text="Exclude KB Info", variable=exclude_kb_on, style="Switch.TCheckbutton")
exclude_kb.pack(side=RIGHT)

# vsTitle is set to global so that it's updated automatically when you change VULNSIGS version.
global vsTitle
if keyring.get_password("QIDentifier.VS_VER", "VS") == None:
    vsText = "VulnSigs Sandbox: VERSION NOT CONFIGURED"
elif keyring.get_password("QIDentifier.VS_VER", "VS") != "":
    vsText = "VulnSigs Sandbox: " + keyring.get_password("QIDentifier.VS_VER", "VS")

vsTitle = ttk.Label(midframe, text=vsText, font=arialbold)
vsTitle.pack(side=LEFT, padx=5)

kbTitle = ttk.Label(midframe, text="Qualys Knowledgebase", font=arialbold)
kbTitle.pack(side=RIGHT, padx=5)

#define the VS Signatures Notebook
leftbook = ttk.Notebook(bottomframe)
leftbook.pack(side=LEFT, fill=BOTH, expand=True)

#VULNSIGS notebook, signatures page
lb_tab1 = ttk.Frame(leftbook)
for index in [0, 1]:
    lb_tab1.columnconfigure(index=index, weight=1)
    lb_tab1.rowconfigure(index=index, weight=1)
leftbook.add(lb_tab1, text="Signatures")

vso_sigs = Text(lb_tab1, font=arial, wrap=WORD)
vso_sigs.pack(expand=True, fill=BOTH)

#VULNSIGS notebook, functions page
lb_tab2 = ttk.Frame(leftbook)
leftbook.add(lb_tab2, text="Functions")
vso_funcs = Text(lb_tab2, font=arial, wrap=WORD)
vso_funcs.pack(expand=True, fill=BOTH)

#define KB Output Notebook
rightbook = ttk.Notebook(bottomframe)
rightbook.pack(side=LEFT, fill=BOTH, expand=True)

#KBO Notebook, main page
rb_tab1 = ttk.Frame(rightbook)
for index in [0, 1]:
    rb_tab1.columnconfigure(index=index, weight=1)
    rb_tab1.rowconfigure(index=index, weight=1)
rightbook.add(rb_tab1, text="General")

kbo_main = Text(rb_tab1, font=arial, wrap=WORD)
kbo_main.pack(expand=True, fill=BOTH)
kbo_main.insert(END, "Pulling KB information may take some time.\n\nIf you don't need it, enable the setting above.")

#KBO Notebook, threat page
rb_tab2 = ttk.Frame(rightbook)
rightbook.add(rb_tab2, text="Threat")
kbo_threat = Text(rb_tab2, font=arial, wrap=WORD)
kbo_threat.pack(expand=True, fill=BOTH)
kbo_threat.insert(END, "Pulling KB information may take some time.\n\nIf you don't need it, enable the setting above.")

#KBO Notebook, solution page
rb_tab3 = ttk.Frame(rightbook)
rightbook.add(rb_tab3, text="Solution")
kbo_solution = Text(rb_tab3, font=arial, wrap=WORD)
kbo_solution.pack(expand=True, fill=BOTH)
kbo_solution.insert(END, "Pulling KB information may take some time.\n\nIf you don't need it, enable the setting above.")

#KBO Notebook, CVE page
rb_tab4 = ttk.Frame(rightbook)
rightbook.add(rb_tab4, text="CVE")
kbo_cve = Text(rb_tab4, font=arial, wrap=WORD)
kbo_cve.pack(expand=True, fill=BOTH)
kbo_cve.insert(END, "Pulling KB information may take some time.\n\nIf you don't need it, enable the setting above.")

"""def loadstart():
    def true_loadstart():
        loadingindicator.pack(side=LEFT)
        loadingindicator.start()
        time.sleep(5)
        loadingindicator.stop()
        loadingindicator.grid_forget()

        settings['state']='normal'

    settings['state']='disabled'
    threading.Thread(target=true_loadstart, args=(1,)).start()"""

settings = ttk.Button(footerframe, text="Settings", command=lambda: settingspane())
settings.pack(side=RIGHT)

#loadingindicator = ttk.Progressbar(footerframe, orient='horizontal', mode='indeterminate', length=100)

# Execute Tkinter
root.mainloop()
