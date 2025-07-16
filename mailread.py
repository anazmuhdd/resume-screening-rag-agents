import time
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import base64
import email

SCOPES = ['https://www.googleapis.com/auth/gmail.modify']  # allow modifying labels

def authenticate():
    flow = InstalledAppFlow.from_client_secrets_file('credentials.json', scopes=SCOPES)
    creds = flow.run_local_server(port=5000)
    service = build('gmail', 'v1', credentials=creds)
    return service

def get_primary_messages(service, MAX_RESULTS=5):
    results = service.users().messages().list(
        userId='me',
        labelIds=['INBOX', 'CATEGORY_PERSONAL'],
        maxResults=MAX_RESULTS,
        q='is:unread'
    ).execute()
    
    messages = results.get('messages', [])
    if not messages:
        print("No new unread emails in Primary.")
        return

    for msg in messages:
        msg_data = service.users().messages().get(userId='me', id=msg['id'], format='full').execute()
        payload = msg_data['payload']
        headers = payload['headers']
        subject = sender = ''
        for header in headers:
            if header['name'] == 'Subject':
                subject = header['value']
            if header['name'] == 'From':
                sender = header['value']
        
        print(f"\nNew Email:")
        print(f"From: {sender}")
        print(f"Subject: {subject}")

        body = ""
        if 'parts' in payload:
            for part in payload['parts']:
                if part['mimeType'] == 'text/plain':
                    data = part['body'].get('data')
                    if data:
                        text = base64.urlsafe_b64decode(data).decode()
                        body = text.strip()
                        break
        else:
            data = payload['body'].get('data')
            if data:
                text = base64.urlsafe_b64decode(data).decode()
                body = text.strip()

        print(f"Body Preview:\n{body[:300]}\n")

        # Mark as read to avoid reprocessing
        service.users().messages().modify(
            userId='me',
            id=msg['id'],
            body={'removeLabelIds': ['UNREAD']}
        ).execute()

def monitor_loop(service, interval=1):
    print("Starting Gmail listener...")
    while True:
        try:
            get_primary_messages(service)
            time.sleep(interval)
        except Exception as e:
            print(f"Error: {e}")
            time.sleep(60)

if __name__ == '__main__':
    service = authenticate()
    monitor_loop(service)
