#QIDentifier
A tool for pulling QID information from Qualys sources

###Prerequisites:
* Install Python 3 (https://www.python.org/downloads/)
* Open the 'QIDentifier' folder in a CLI, run "pip install -r requirements.txt"
* Run the application from 'src/main.py'

###Getting Started:
Before searching for QID information, there's a couple things to get set up:
* Click 'Settings' in the bottom right corner of the screen.
* Configure your Qualys API POD/Credentials, and click 'Set Credentials'.
  * This can be any Qualys account with API permissions. A Manager user is recommended.
* Select the most recent VULNSIGS Version for signature definitions, and click "Set Version".
  * You can change the VULNSIGS Version for your search at any time. This is useful for determining changes made to QIDs.
* Once finished, click 'Done'.

###Using QIDentifier:
It's super easy. Punch in a QID and hit "Go".


#####Some things to note:
* Qualys Knowledgebase search speed is entirely dependent on the API and can take anywhere between 10 and 30 seconds on average.
  * If you only need signatures, enable the "Exclude KB Info" setting.
* VULNSIGS data is split between 'Signatures' and 'Functions', which combine to form a detection method for QIDs.
  * You can alternate between these using the output box tabs with the appropriate labels.
