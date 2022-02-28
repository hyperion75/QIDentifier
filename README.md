# QIDentifier
A tool for pulling QID/DPID information from Qualys sources

### Prerequisites:
* Install Python 3 (https://www.python.org/downloads/)
* Open the 'QIDentifier' folder in a CLI, run "pip install -r requirements.txt"
* Run the application from 'src/main.py'

### Getting Started:
Before searching for QID/DPID information, there's a couple things to get set up:
* Click 'Settings' in the bottom right corner of the screen.
* Input your Qualys Corp Credentials and click 'Set Credentials'.
  * These are encrypted and stored in the system keychain so that they do not need to be set every launch.
  * These credentials are used to access VulnSigs Sandbox and VulnOffice for QID/DPID information.


## Vulnerability Management (VM) Mode

### QID Search
* To search for QID information, type the QID # in the search bar and click "Go".
* The left side of the UI will contain Signature/Function information sourced from VulnSigs Sandbox.
  * By default, this information is pulled using the latest VulnSigs version. You can change the VulnSigs version from the "Settings" menu.
* The right side of the UI will contain Qualys Knowledgebase information for the QID split into three tabs:
  * General: Title, Vuln Type, Severity, CVSS, Vendor, Product, Supported Auth Types, Supported Products
  * Detail: Diagnosis, Consequence, Solution, Threat Identifiers
  * Reference: CVE(s), Vendor Reference(s)

### CVE Search
* You can see if any QIDs are related to a CVE by inputting the CVE in the search bar and clicking "Go".
* The right side of the UI will contain a list of all related QIDs (if applicable).
  * QIDs beginning with "QA-" (e.g. QA-159620) are in the QA stage and are currently unreleased.
* If a CVE does not have any related QIDs, you will recieve the message "The provided CVE does not match Qualys records."


## Policy Compliance (PC) Mode

### CID Search
* To search for CID/DPID information, type the CID # in the search bar and click "Go".
* The left side of the UI will contain Signature/Function information sourced from VulnSigs Sandbox.
  * This will contain ALL related DPIDs for the control. Each signature will have the Control DPID # listed above it. You can verify your OS DPID # on the right.
  * By default, this information is pulled using the latest VulnSigs version. You can change the VulnSigs version from the "Settings" menu.
* The right side of the UI will contain Qualys Knowledgebase information for the CID split into two tabs:
  * General: Title, Criticality, Category, Subcategory, Supported Technologies
  * Detail: (For each applicable technology:) Control DPID, Created/Updated Date, Rationale, Remediation, Comments


## Extended Functionality

### Open in JIRA
* Opens your search term (QID/CID/CVE) in Jira.
* Use in conjunction with QID/CID/CVE search to track development or any issues.

### Regex Tester
* Used to test customer results against signatures.
* Enter the regex from the signature (QID/DPID) in the "Expression" field, and the test results in the "Test String" field.
* Click "Test" - The "Test" button will now indicate whether there was a match or not.
* If text in the results was flagged by the signature expression, it will turn red in the "Test String" field.
