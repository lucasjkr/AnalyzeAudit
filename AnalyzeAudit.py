import argparse, csv, json, msal, requests, logging, os, time
from datetime import timedelta
from datetime import datetime
from dotenv import dotenv_values
from pathlib import Path
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill


class analyze_audit():
    input: str

    def __init__(self):
        # load values for API keys from .env file
        self.config = dotenv_values()

        # ip_ignore_list .env entry to JSON list. If entry doesn't exist in .env file, then create an empty list
        self.ip_ignore_list = json.loads( self.config.get('IP_IGNORE_LIST', "[]") )

        self.counter = {
            'messages': 0,
            'rules': 0,
            'file_operations': 0,
            'logins': 0,
            'start_time': time.time()
        }

        self.input = ""
        self.output = {}

        self.mail_writer = None
        self.rule_writer = None
        self.file_writer = None
        self.login_writer = None

        # bearer token for Graph API
        # make sure the first token is already expired
        self.token_expires_at = datetime.now() + timedelta(hours=-1)
        self.token = ""

        self.workbook = None

    def create_empty_workbook(self):
        self.workbook = Workbook()
        del self.workbook[self.workbook.sheetnames[0]]

    def write_to_worksheet(self, sheet, data):
        # If worksheet doesnt exist, then create worksheet and write header row followed by values.
        if sheet not in self.workbook:
            worksheet = self.workbook.create_sheet(title=sheet)
            worksheet.append(list(data.keys()))

        worksheet = self.workbook[sheet]
        worksheet.append(list(data.values()))


    def get_bearer_token(self):
        # code for retrieving a Graph token, slightly adapted from Microsofts example code
        app = msal.ConfidentialClientApplication(
            self.config['CLIENT_ID'],
            authority="https://login.microsoftonline.com/" + self.config['TENANT_ID'],
            client_credential=self.config['SECRET'],
        )
        result = app.acquire_token_silent(["https://graph.microsoft.com/.default"], account=None)
        if not result:
            logging.info("No suitable token exists in cache. Let's get a new one from AAD.")
            result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])

        if "access_token" in result:
            logging.info("Authentication succeeded. Token acquired")
            # return result["access_token"]
            return result

        else:
            logging.critical("Authentication failed: " + result.get("error_description", "No error description available"))
            raise Exception(
                "Authentication failed: " + result.get("error_description", "No error description available"))

    def bearer_token(self):
        if datetime.now() > self.token_expires_at:
            token_response = self.get_bearer_token()
            self.token = token_response["access_token"]
            self.token_expires_at = datetime.today() + timedelta(seconds=800)
            return self.token
        else:
            return self.token

    # Scans an audit export and displays the operations occurring with in. Useful to determine whether new functions,
    # parsers or outputs need to be coded.
    def show_operations(self):
        with open(self.input) as csv_file:
            operations = []
            csv_reader = csv.DictReader(csv_file)
            for row in csv_reader:
                if row['Operation'] not in operations:
                    operations.append(row['Operation'])
        for op in sorted(operations):
            print(op)

    # Looks up each message from the Graph API in order to obtain metadata to assist with the review.
    def get_message(self, user, internet_message_id):
        # retrieve message metadata from Graph, searching by InternetMessageId
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + self.bearer_token()
        }
        return requests.get(
            f"https://graph.microsoft.com/v1.0/users/{user}/messages?$filter=internetMessageId eq '{internet_message_id}'",
            headers=headers).json()

    def analyze_mail_rule(self, row):
        audit_data = json.loads(row['AuditData'])

        for param in json.loads(row['AuditData'])['Parameters']:

            # if Name in the Parameters, then this is a New Inbox Rule
            if row['Operation'] == "New-InboxRule" and param['Name'] == "Name":
                export = {
                    'datetime': row.get('CreationDate', ""),
                    'user': row.get('UserId', ""),
                    'operation': row.get('Operation', ""),
                    'ip': audit_data.get('ClientIP', ""),
                    'value': param.get('Value'),
                }

                self.write_to_worksheet('rules', export)
                self.counter['rules'] += 1

            elif row['Operation'] == "Remove-InboxRule" and param['Name'] == "AlwaysDeleteOutlookRulesBlob":
                export = {
                    'datetime': row['CreationDate'],
                    'user': row['UserId'],
                    'operation': row['Operation'],
                    'ip': audit_data['ClientIP'],
                    'value': ""
                }
                self.write_to_worksheet('rules', export)
                self.counter['rules'] += 1

    def analyze_mail_access(self, row):
        audit_data = json.loads(row['AuditData'])
        for item in audit_data['Folders'][0]['FolderItems']:

            # If clientIP is in the IP ignore list, ignore and move to next
            if audit_data['ClientIPAddress'] in self.ip_ignore_list:
                continue

            export = {
                'CreationDate': row['CreationDate'],
                'UserId': row['UserId'],
                'Operation': row['Operation'],
                'ClientIP': audit_data['ClientIPAddress'],
                'MailClient': audit_data['ClientInfoString'],
                'MailAccessType': audit_data['OperationProperties'][0]['Value'],
                'Throttled': audit_data['OperationProperties'][1]['Value'],
                'OperationCount': audit_data['OperationCount'],
                'InternetMessageId': item['InternetMessageId']
            }

            # retrieve message metadata from Microsoft
            message = self.get_message(export['UserId'], export['InternetMessageId'])

            # If data in any of these fields is missing, then the message was deleted long enough ago that metadata cannot be retrieved. Auditlog will still reflect the internet message id that was retrieved but nothing more.
            # retrieve message metadata from Microsoft
            try:
                date = message['value'][0]['receivedDateTime']
            except Exception as e:
                date = ""

            try:
                sender = message['value'][0]['from']['emailAddress']['address']
            except Exception as e:
                sender = ""

            try:
                sender_name = message['value'][0]['from']['emailAddress']['name']
            except Exception as e:
                sender_name = ""

            try:
                mail_folder = audit_data['Folders'][0]['Path']
            except Exception as e:
                mail_folder = ""

            try:
                subject = message['value'][0]['subject']
            except Exception as e:
                subject = ""

            try:
                link = message['value'][0]['webLink']
            except Exception as e:
                link = ""

            # update the export dictionary and write line to file
            export.update({
                'folder': mail_folder,
                'date': date,
                'sender': sender,
                'sender_name': sender_name,
                'subject': subject,
                'link': link
            })
            self.write_to_worksheet('mail', export)
            self.counter['messages'] +=1

    def analyze_mail_delete(self, row):
        audit_data = json.loads(row['AuditData'])
        for item in audit_data['AffectedItems']:
            export = {
                'CreationDate': row['CreationDate'],
                'UserId': row['UserId'],
                'Operation': row['Operation'],
                'ClientIP': audit_data['ClientIPAddress'],
                'MailClient': audit_data['ClientInfoString'],
                'MailAccessType': 'Delete',
                'Throttled': '',
                'OperationCount': '',
                'InternetMessageId': item['InternetMessageId']
            }

            # If clientIP is in the IP ignore list, ignore and move to next
            if audit_data['ClientIPAddress'] in self.ip_ignore_list:
                continue

            # retrieve message metadata from Microsoft
            message = self.get_message(export['UserId'], export['InternetMessageId'])

            # If data in any of these fields is missing, then the message was deleted long enough ago that metadata cannot be retrieved. Auditlog will still reflect the internet message id that was retrieved but nothing more.
            try:
                date = message['value'][0]['receivedDateTime']
            except Exception as e:
                date = ""

            try:
                sender = message['value'][0]['from']['emailAddress']['address']
            except Exception as e:
                sender = ""

            try:
                sender_name = message['value'][0]['from']['emailAddress']['name']
            except Exception as e:
                sender_name = ""

            try:
                mail_folder = audit_data['Folders'][0]['Path']
            except Exception as e:
                mail_folder = ""

            try:
                subject = message['value'][0]['subject']
            except Exception as e:
                subject = ""

            try:
                link = message['value'][0]['webLink']
            except Exception as e:
                link = ""

            # update the export dictionary and write line to file
            export.update({
                'folder': mail_folder,
                'date': date,
                'sender': sender,
                'sender_name': sender_name,
                'subject': subject,
                'link': link
            })
            self.write_to_worksheet('mail', export)
            self.counter['messages'] += 1

    def analyze_mail_send(self, row):
        audit_data = json.loads(row['AuditData'])
        export = {
            'CreationDate': row['CreationDate'],
            'UserId': row['UserId'],
            'Operation': row['Operation'],
            'ClientIP': audit_data['ClientIPAddress'],
            'MailClient': audit_data['ClientInfoString'],
            'MailAccessType': 'Send',
            'Throttled': '',
            'OperationCount': '',
            'InternetMessageId': audit_data['Item']['InternetMessageId']
        }

        # retrieve message metadata from Microsoft
        message = self.get_message(export['UserId'], export['InternetMessageId'])

        # If data in any of these fields is missing, then the message was deleted long enough ago that metadata cannot be retrieved. Auditlog will still reflect the internet message id that was retrieved but nothing more.
        try:
            date = message['value'][0]['sentDateTime']
        except Exception as e:
            date = ""

        try:
            sender = message['value'][0]['from']['emailAddress']['address']
        except Exception as e:
            sender = ""

        try:
            sender_name = message['value'][0]['from']['emailAddress']['name']
        except Exception as e:
            sender_name = ""

        try:
            mail_folder = audit_data['Folders']['Path']
        except Exception as e:
            mail_folder = ""

        try:
            subject = message['value'][0]['subject']
        except Exception as e:
            subject = ""

        try:
            link = message['value'][0]['webLink']
        except Exception as e:
            link = ""

        # update the export dictionary and write line to file
        export.update({
            'folder': mail_folder,
            'date': date,
            'sender': sender,
            'sender_name': sender_name,
            'subject': subject,
            'link': link
        })
        self.write_to_worksheet('mail', export)
        self.counter['messages'] +=1

    def analyze_file_folder_operations(self, row):
        audit_data = json.loads(row['AuditData'])
        export = {
            'date': audit_data['CreationTime'],
            'operation': audit_data['Operation'],
            'app_used': audit_data['AppAccessContext']['ClientAppName'],
            'item_type': audit_data['ItemType'],
            # 'item_site_url': audit_data['SiteUrl'],
            # 'item_path': audit_data['SourceRelativeUrl'],
            'file_name': audit_data['SourceFileName'],
            'full_url': f"{audit_data['SiteUrl']}/{audit_data['SourceRelativeUrl']}/{audit_data['SourceFileName']}",

            'user': audit_data.get('UserId', ""),
            'client_ip': audit_data.get('ClientIP', ""),
            'auth_type': audit_data.get('AuthenticationType', ""),
            'event_source': audit_data.get('EventSource', ""),
            'managed_device': audit_data.get('IsManagedDevice', ""),
            'user_agent': audit_data.get('UserAgent', ""),
            'device_platform': audit_data.get('Platform', ""),
        }
        self.write_to_worksheet('files', export)
        self.counter['file_operations'] += 1

    def analyze_login_events(self, row):
        audit_data = json.loads(row['AuditData'])
        export = {
            'date': audit_data.get('CreationTime', ""),
            'operation': audit_data['Operation'],
            'workload': audit_data.get('Workload', ""),
            'username': audit_data.get('UserId', ""),
            'ip': audit_data.get('ClientIp', ""),
            'status': "",
            'user_agent': "",
            'result': "",
            'device_name': "",
            'device_os': ""
        }

        for prop in audit_data['ExtendedProperties']:
            if prop['Name'] == "ResultStatusDetail":
                export['status'] = prop['Value']
            elif prop['Name'] == "UserAgent":
                export['user_agent'] = prop['Value']
            if prop['Name'] == "RequestType":
                export['result'] = prop['Value']

        for prop in audit_data['DeviceProperties']:
            if prop['Name'] == "DisplayName":
                export['device_name'] = prop['Value']
            elif prop['Name'] == "OS":
                export['device_os'] = prop['Value']

        self.write_to_worksheet('logins', export)
        self.counter['logins'] += 1

    def analyze_signin_events(self, row):
        audit_data = json.loads(row['AuditData'])
        export = {
            'date': audit_data.get('CreationTime', ""),
            'operation': audit_data['Operation'],
            'workload': audit_data.get('Workload', ""),
            'username': audit_data.get('UserId', ""),
            'ip': audit_data.get('ClientIp', ""),
            'status': "",
            'user_agent': audit_data.get('UserAgent'),
            'result': "",
            'device_name': "",
            'device_os': audit_data.get("Platform"),
        }
        self.write_to_worksheet('logins', export)
        self.counter['logins'] += 1

    def save_and_cleanup_excel_files(self):
        for sheet in self.workbook.sheetnames:
            worksheet = self.workbook[sheet]

            # bump up fon font size and change URLs into working hyperlinks
            for row in worksheet:
                for cell in row:
                    cell.font = Font(size=13)
                    # create hyperlinks in cells that look like they are hyperlinks
                    if type(cell.value) is str and cell.value.startswith("https://") == True:
                        cell.hyperlink = cell.value
                        cell.value = "View on the Web"
                        cell.style = "Hyperlink"

            # Make the entire first row bold
            for cell in worksheet[1]:
                cell.font = Font(bold=True, size=13)
                cell.fill = PatternFill(start_color="ededed", end_color="ededed", fill_type="solid")

            # Iterate over all columns and adjust their widths
            # https://python-bloggers.com/2023/05/how-to-automatically-adjust-excel-column-widths-in-openpyxl/
            for column in worksheet.columns:
                max_length = 0
                column_letter = column[0].column_letter
                for cell in column:
                    try:
                        if len(str(cell.value)) > max_length:
                            max_length = len(cell.value)
                    except:
                        pass
                adjusted_width = (max_length + 2) * 1.1
                worksheet.column_dimensions[column_letter].width = adjusted_width

            # Freeze the header row - openpyxl freezes starting at the row and column BEFORE the cell referenced, so
            # this will freeze the first row
            # https://www.codespeedy.com/freeze-header-rows-in-openpyxl-python/
            worksheet.freeze_panes = 'A2'

        self.workbook.save(f"data{os.sep}{Path(self.input).stem}.xlsx")

    def execute(self):
        self.create_empty_workbook()

        with open(self.input) as csv_file:
            csv_reader = csv.DictReader(csv_file)
            for row in csv_reader:

                # If operation contains "Rule" (as in New-InboxRule, Remove-InboxRule or any other, then it could indicate
                # a threat actor has modified inbox rules. The user should review the created/changed rules and delete
                # if it's malicious
                if "Rule" in row['Operation']:
                    self.analyze_mail_rule(row)

                # When AuditData contains "Folders", that indicates it contains records of mail items accessed. Anything else will be ignored for now.
                # In the future, should report on mailbox rules being created, and eventually OneDrive/Sharepoint activity. Also should somehow alert
                # when it finds "Sync" events rather than "Bind", and when Throttled is true.
                #
                # * Sync means the entire mailbox was synced, rather than just batches of messages being retrieved.
                # * Bind just means one or more messages retrieved
                # * Throttled means that logging was throttled - more messages were retrieved than the logs show
                # elif 'Folders' in audit_data:
                elif row['Operation'] == "MailItemsAccessed" and "Folders" in row['AuditData']:
                    self.analyze_mail_access(row)

                # do the same for any messages moved to deleted items
                elif row['Operation'] == "MoveToDeletedItems":
                    self.analyze_mail_delete(row)

                # compile Sent Messages in the same way
                elif row['Operation'] == "Send":
                    self.analyze_mail_send(row)

                # OneDrive and Sharepoint Operations
                elif "File" in row['Operation'] or "Folder" in row['Operation']:
                    self.analyze_file_folder_operations(row)

                elif "UserLoggedIn" in row['Operation'] or "UserLoginFailed" in row['Operation']:
                    self.analyze_login_events(row)

                elif row['Operation'] == "SignInEvent":
                    self.analyze_signin_events(row)

                self.save_and_cleanup_excel_files()

        end_time = time.time()
        duration = end_time - self.counter['start_time']
        print(duration)

        print(f"{self.counter['messages']} mailbox messages")
        print(f"{self.counter['rules']} mailbox rule events")
        print(f"{self.counter['file_operations']} file operations")
        print(f"{self.counter['logins']} logins")

    def main(self):
        args = argparse.ArgumentParser()
        args.add_argument('--ops',
                            default=False,
                            action="store_true",
                            help="(optional) Enter the email (user@example.com) of the user")
        args.add_argument('input_file',
                            nargs='?',
                            default=None,
                            help="(optional) Enter the email (user@example.com) of the user")
        arg = args.parse_args()
        self.input = Path(arg.input_file)

        if arg.ops == True:
            self.show_operations()
            exit()

        if arg.ops == False and arg.input_file != None:
            self.input = arg.input_file
            self.execute()
            exit()

if __name__ == "__main__":
    analyze = analyze_audit()
    analyze.main()



