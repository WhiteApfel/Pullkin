from os import getenv

from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())

SENDER_ID = getenv('FIREBASE_SENDER_ID')
print(SENDER_ID)
