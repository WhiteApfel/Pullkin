import firebase_admin
import pytest_asyncio
from firebase_admin import credentials, messaging

from tests.testdata import SERVICE_ACCOUNT_CRED


class FirebaseAdmin:
    def __init__(self):
        self.cred = credentials.Certificate(SERVICE_ACCOUNT_CRED)
        self.app_fcm = firebase_admin.initialize_app(self.cred)

    def send_notification(
        self, token: str, title: str, body: str, image: str = None, data: dict = None
    ):
        messaging.send(
            message=messaging.Message(
                token=token,
                data=data,
                notification=messaging.Notification(
                    title=title, body=body, image=image
                ),
            ),
            dry_run=False,
            app=None,
        )


@pytest_asyncio.fixture(scope="function")
async def fcm(event_loop, monkeypatch):
    return FirebaseAdmin()
