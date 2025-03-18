# AnalyzeAudit
Analyzes a csv exported from Purviews Audit Search and parses for email and file activity, returns an XLSX spreadsheet 
of activity sorted into tabs with clickable hyperlinks to assist with User review


## Requirements 
* NEEDS to be run under Linux (or Windows Subsystem for Linux) - running under Window can result in UnicodeDecodeErrors which I can't resolve yet.
* Also requires sqlite3 for requests_cache

##
Initial setup

    pip install -r requirements.txt

Usage 

    python3 AnalyzeAudit.py export.csv

Returns an excel file with different tabs showing user activity showing mail items accessed, mail sent, mail deleted, 
file and folder actions in OneDrive/Sharepoint:


