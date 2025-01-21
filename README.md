# AnalyzeAudit
 
Input - a csv export from Purview's activity log

Initial setup

    pip install -r requirements.txt

Usage 

    python3 AnalyzeAudit.py export.csv

Returns an excel file with different tabs showing user activity showing mail items accessed, mail sent, mail deleted, 
file and folder actions in OneDrive/Sharepoint:


