# AnalyzeAudit
Analyzes a csv exported from Purviews Audit Search and parses for email and file activity, returns an XLSX spreadsheet 
of activity sorted into tabs with clickable hyperlinks to assist with User review

This scans an audit file exported from Purview and creates an excel Spreadsheet with the following data:

* mail items accessed
* mailbox sync events
* mail sent
* mail deleted
* mailbox rule creation
* file and folder activity in OneDrive or Sharepoint

## Requirements 
* NEEDS to be run under Linux (or Windows Subsystem for Linux) - running under Window can result in UnicodeDecodeErrors which I can't resolve yet.
* Also requires sqlite3 for requests_cache
* Azure App Registration with the `Mail.ReadBasic.All` application permission.

## Initial setup

Create `.env` file 

    cp .env.example .env

Populate `.env` with your Azure Tenant ID, Application ID and Secret. If there are IP addresses which should be omitted 
from reporting, add them to the `IP_IGNORE_LIST`. Typically, the only IP's you'll want in the list are the IP addresses 
used by whichever services you're using to backup Exchange mailboxes

Install requirements

    pip install -r requirements.txt

## Usage 

    python3 AnalyzeAudit.py path/to/export.csv


