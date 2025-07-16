import time
import os
import base64
from bs4 import BeautifulSoup
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

SCOPES = ['https://www.googleapis.com/auth/gmail.modify']

def authenticate():
    flow = InstalledAppFlow.from_client_secrets_file('credentials.json', scopes=SCOPES)
    creds = flow.run_local_server(port=5000)
    service = build('gmail', 'v1', credentials=creds)
    return service

def decode_base64_data(data):
    return base64.urlsafe_b64decode(data).decode(errors='ignore')

def extract_email_body(payload):
    def get_parts(parts):
        for part in parts:
            mime = part.get("mimeType")
            body_data = part.get("body", {}).get("data")
            sub_parts = part.get("parts", [])

            if sub_parts:
                result = get_parts(sub_parts)
                if result:
                    return result

            if mime == "text/plain" and body_data:
                return decode_base64_data(body_data).strip()

        for part in parts:
            mime = part.get("mimeType")
            body_data = part.get("body", {}).get("data")
            if mime == "text/html" and body_data:
                html = decode_base64_data(body_data)
                soup = BeautifulSoup(html, "html.parser")
                return soup.get_text().strip()

        return "[No body text found]"

    if "parts" not in payload:
        data = payload.get("body", {}).get("data")
        if data:
            return decode_base64_data(data).strip()

    return get_parts(payload["parts"])

def download_attachment(service, msg_id, store_dir='resumes'):
    msg = service.users().messages().get(userId='me', id=msg_id, format='full').execute()

    def save_parts(parts):
        for part in parts:
            filename = part.get("filename")
            body = part.get("body", {})
            sub_parts = part.get("parts", [])

            if sub_parts:
                save_parts(sub_parts)

            if filename and (filename.endswith('.pdf') or filename.endswith('.docx')):
                att_id = body.get("attachmentId")
                if att_id:
                    attachment = service.users().messages().attachments().get(
                        userId='me', messageId=msg_id, id=att_id
                    ).execute()

                    data = base64.urlsafe_b64decode(attachment['data'])
                    os.makedirs(store_dir, exist_ok=True)
                    filepath = os.path.join(store_dir, filename)

                    with open(filepath, 'wb') as f:
                        f.write(data)

                    print(f"Saved to: {filepath}")

    parts = msg.get("payload", {}).get("parts", [])
    save_parts(parts)

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
        print(f"Subject: {subject}\n")
        print(f"Messages: {messages}\n")

        body = extract_email_body(payload)
        print(f"Body Preview:\n{body[:20000]}\n")

        download_attachment(service, msg['id'])

        service.users().messages().modify(
            userId='me',
            id=msg['id'],
            body={'removeLabelIds': ['UNREAD']}
        ).execute()

def monitor_loop(service, interval=10):
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
