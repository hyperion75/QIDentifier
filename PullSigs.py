from bs4 import BeautifulSoup
import requests as requests
import keyring

# Pulls Vulnerability Signatures from sandbox. No credentials are needed, runs pretty quick.
# In the future I'd like to split up returned vuln data and display it cleaner in the UI
# Right now, it just condenses all entries into one big scrollable list. It works, but it's gross.
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
    print(response.status_code)

    soup = BeautifulSoup(response.content, 'html.parser')

    parsed = list(soup.find_all('div', class_='panel-body'))
    siglist = []
    for x in parsed:
        siglist.append(x.get_text() + '\n' + "================")
    sigs = '\n\n'.join(siglist)

    if response.status_code != 200:
        sigs = 'Connection Error'
    return sigs
