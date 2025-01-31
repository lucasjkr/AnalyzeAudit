# AnalyzeAudit
 
Input - a csv export from Purview's activity log

## Requirements
* Python3
* Sqlite 3

## Initial setup

    pip install -r requirements.txt

## Usage 

__Analyze Audit file__

Returns an excel file with different tabs showing user activity showing mail items accessed, mail sent, mail deleted, 
file and folder actions in OneDrive/Sharepoint:

    python3 AnalyzeAudit.py export.csv

__Get Operations from Audit file__

Analyze Audit file and print list of operations within it (useful for determining whether new logic needs to be written)

    python3 AnalyzeAudit.py export.csv --ops



