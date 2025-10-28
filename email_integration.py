"""
Conners Group AI Assistant - Email Integration Module
Supports Gmail and Proton Mail integration
"""

import os
from pathlib import Path

try:
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build
    from googleapiclient.errors import HttpError
except ImportError:
    print("Warning: Google API libraries not installed. Email integration disabled.")
    print("Run: pip install google-auth google-auth-oauthlib google-api-python-client")

import base64
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import pickle

# Gmail API Scopes
GMAIL_SCOPES = ['https://www.googleapis.com/auth/gmail.modify']

class EmailIntegration:
    """Handles email integration for Gmail and Proton Mail"""
    
    def __init__(self):
        self.gmail_service = None
        self.credentials_path = Path('credentials')
        self.credentials_path.mkdir(exist_ok=True)
    
    def authenticate_gmail(self):
        """Authenticate with Gmail API"""
        try:
            creds = None
            token_path = self.credentials_path / 'gmail_token.pickle'
            
            if token_path.exists():
                with open(token_path, 'rb') as token:
                    creds = pickle.load(token)
            
            if not creds or not creds.valid:
                if creds and creds.expired and creds.refresh_token:
                    creds.refresh(Request())
                else:
                    credentials_json = self.credentials_path / 'gmail_credentials.json'
                    if not credentials_json.exists():
                        raise Exception("Gmail credentials file not found. Please download from Google Cloud Console.")
                    
                    flow = InstalledAppFlow.from_client_secrets_file(
                        str(credentials_json), GMAIL_SCOPES)
                    creds = flow.run_local_server(port=0)
                
                with open(token_path, 'wb') as token:
                    pickle.dump(creds, token)
            
            self.gmail_service = build('gmail', 'v1', credentials=creds)
            return True
        except Exception as e:
            raise Exception(f"Gmail authentication failed: {str(e)}")
    
    def get_gmail_messages(self, max_results=10, query=''):
        """Get Gmail messages"""
        try:
            if not self.gmail_service:
                self.authenticate_gmail()
            
            results = self.gmail_service.users().messages().list(
                userId='me', 
                maxResults=max_results,
                q=query
            ).execute()
            
            messages = results.get('messages', [])
            
            detailed_messages = []
            for message in messages:
                msg = self.gmail_service.users().messages().get(
                    userId='me', 
                    id=message['id'],
                    format='full'
                ).execute()
                
                headers = msg['payload']['headers']
                subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
                sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown')
                date = next((h['value'] for h in headers if h['name'] == 'Date'), '')
                
                body = ''
                if 'parts' in msg['payload']:
                    for part in msg['payload']['parts']:
                        if part['mimeType'] == 'text/plain' and 'data' in part['body']:
                            body = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
                            break
                elif 'body' in msg['payload'] and 'data' in msg['payload']['body']:
                    body = base64.urlsafe_b64decode(msg['payload']['body']['data']).decode('utf-8')
                
                detailed_messages.append({
                    'id': message['id'],
                    'subject': subject,
                    'from': sender,
                    'date': date,
                    'snippet': msg.get('snippet', ''),
                    'body': body
                })
            
            return detailed_messages
        except Exception as e:
            raise Exception(f"Gmail API error: {str(e)}")
    
    def send_gmail(self, to, subject, body, attachments=None):
        """Send email via Gmail"""
        try:
            if not self.gmail_service:
                self.authenticate_gmail()
            
            message = MIMEMultipart()
            message['to'] = to
            message['subject'] = subject
            
            message.attach(MIMEText(body, 'plain'))
            
            if attachments:
                for file_path in attachments:
                    with open(file_path, 'rb') as file:
                        part = MIMEBase('application', 'octet-stream')
                        part.set_payload(file.read())
                        encoders.encode_base64(part)
                        part.add_header('Content-Disposition', f'attachment; filename={Path(file_path).name}')
                        message.attach(part)
            
            raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
            send_message = {'raw': raw}
            
            result = self.gmail_service.users().messages().send(
                userId='me',
                body=send_message
            ).execute()
            
            return {
                'success': True,
                'message_id': result['id']
            }
        except Exception as e:
            raise Exception(f"Error sending email: {str(e)}")
    
    def send_proton_mail(self, to, subject, body):
        """Send email via Proton Mail using SMTP Bridge"""
        import smtplib
        
        try:
            smtp_server = "127.0.0.1"
            smtp_port = 1025
            
            username = os.getenv('PROTON_EMAIL')
            password = os.getenv('PROTON_PASSWORD')
            
            if not username or not password:
                raise Exception("Proton Mail credentials not configured in .env file")
            
            message = MIMEMultipart()
            message['From'] = username
            message['To'] = to
            message['Subject'] = subject
            message.attach(MIMEText(body, 'plain'))
            
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(username, password)
                server.send_message(message)
            
            return {
                'success': True,
                'message': 'Email sent via Proton Mail'
            }
        except Exception as e:
            raise Exception(f"Proton Mail error: {str(e)}")
    
    def get_proton_messages(self, max_results=10):
        """Get Proton Mail messages using IMAP Bridge"""
        import imaplib
        import email
        from email.header import decode_header
        
        try:
            imap_server = "127.0.0.1"
            imap_port = 1143
            
            username = os.getenv('PROTON_EMAIL')
            password = os.getenv('PROTON_PASSWORD')
            
            if not username or not password:
                raise Exception("Proton Mail credentials not configured")
            
            mail = imaplib.IMAP4(imap_server, imap_port)
            mail.starttls()
            mail.login(username, password)
            mail.select('inbox')
            
            status, messages = mail.search(None, 'ALL')
            email_ids = messages[0].split()
            
            email_ids = email_ids[-max_results:]
            
            detailed_messages = []
            for email_id in reversed(email_ids):
                status, msg_data = mail.fetch(email_id, '(RFC822)')
                
                for response_part in msg_data:
                    if isinstance(response_part, tuple):
                        msg = email.message_from_bytes(response_part[1])
                        
                        subject = decode_header(msg['Subject'])[0][0]
                        if isinstance(subject, bytes):
                            subject = subject.decode()
                        
                        sender = msg.get('From')
                        
                        body = ''
                        if msg.is_multipart():
                            for part in msg.walk():
                                if part.get_content_type() == 'text/plain':
                                    body = part.get_payload(decode=True).decode()
                                    break
                        else:
                            body = msg.get_payload(decode=True).decode()
                        
                        detailed_messages.append({
                            'id': email_id.decode(),
                            'subject': subject,
                            'from': sender,
                            'body': body[:500]
                        })
            
            mail.logout()
            return detailed_messages
        except Exception as e:
            raise Exception(f"Proton Mail IMAP error: {str(e)}")

# Initialize email integration
email_integration = EmailIntegration()