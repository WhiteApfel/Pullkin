import json
from os import getenv

from dotenv import find_dotenv, load_dotenv

load_dotenv(find_dotenv())

SENDER_ID = getenv("FIREBASE_SENDER_ID")
APP_ID = getenv("FIREBASE_APP_ID")
SERVICE_ACCOUNT_CRED = json.loads(getenv("FIREBASE_SERVICE_ACCOUNT"))
SERVER_KEY = getenv("FIREBASE_SERVER_KEY")
API_KEY = getenv("FIREBASE_API_KEY")
ANDROID_CERT = getenv("FIREBASE_ANDROID_CERT")
FIREBASE_NAME = getenv("FIREBASE_NAME")
APP_NAME = getenv("FIREBASE_APP_NAME")
