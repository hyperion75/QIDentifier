# QIDentifier
A tool for pulling QID information from Qualys sources

### Prerequisites:
* Install Python 3 (https://www.python.org/downloads/)
* Open the 'QIDentifier' folder in a CLI, run "pip install -r requirements.txt"
* Run the application from 'src/main.py'

### Getting Started:
Before searching for QID information, there's a couple things to get set up:
* Click 'Settings' in the bottom right corner of the screen.
* Configure your Qualys Corp Credentials, and click 'Set Credentials'.
* Select the most recent VULNSIGS Version for signature definitions, and click "Set Version".
  * You can change the VULNSIGS Version for your search at any time. This is useful for determining changes made to QIDs.
* Once finished, click 'Done'.

### Using QIDentifier:
* It's super easy. Punch in a QID and hit "Go".
* Alternatively, you can click the "QID" button next to the search bar to switch to CVE search mode. This will allow you to see a list of QIDs that include detection logic for the specified CVE.


##### Some things to note:
* VULNSIGS data is split between 'Signatures' and 'Functions', which combine to form a detection method for QIDs.
  * You can alternate between these using the output box tabs with the appropriate labels.
