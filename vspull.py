from bs4 import BeautifulSoup
import requests as requests

# Pulls a list of all available VULNSIGS versions on the sandbox.
# These can be selected via the UI
def vspull():
    url = "https://10.80.8.21/"
    headers = {
        'Connection': 'keep-alive',
        'Accept': '*/*',
        'Accept-Encoding': 'gzip,deflate,br',
        'Accept-Language': 'en-US,en;q=0.9'
    }
    response = requests.request("GET", url, headers=headers, verify=False)
    print(response.status_code)

    soup = BeautifulSoup(response.content, 'html.parser')

    parsed = list(soup.find_all('option'))
    versionlist = []
    for x in parsed:
        versionlist.append(x.get_text())
    return versionlist




