
import os
import pickle
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload

SCOPES = ["https://www.googleapis.com/auth/drive.file"]

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CREDENTIALS_FILE = os.path.join(
    BASE_DIR, "credentials", "client_secret.json"
)
TOKEN_FILE = os.path.join(BASE_DIR, "credentials", "token.pickle")


def get_drive_service():
    creds = None

    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, "rb") as token:
            creds = pickle.load(token)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                CREDENTIALS_FILE, SCOPES
            )
            creds = flow.run_local_server(port=0)

        with open(TOKEN_FILE, "wb") as token:
            pickle.dump(creds, token)

    return build("drive", "v3", credentials=creds)


DRIVE_FOLDER_ID = "1jfvwYfUddPd9NLRF8u36icPu030dzhRI"

def upload_file(file_path, drive_folder_id=DRIVE_FOLDER_ID):
    service = get_drive_service()
    metadata = {"name": os.path.basename(file_path)}

    if drive_folder_id:
        metadata["parents"] = [drive_folder_id]

    media = MediaFileUpload(file_path, resumable=True)
    result = service.files().create(
        body=metadata,
        media_body=media,
        fields="id,name,webViewLink"
    ).execute()

    return result
