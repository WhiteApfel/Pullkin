import pytest

from pullkin import Pullkin
from pullkin.models import AppCredentials
from tests.testdata import (
    ANDROID_CERT,
    API_KEY,
    APP_ID,
    APP_NAME,
    FIREBASE_NAME,
    SENDER_ID,
)


@pytest.mark.asyncio
async def test_aio_registration():
    client = Pullkin()
    credentials = await client.register(
        SENDER_ID, APP_ID, API_KEY, FIREBASE_NAME, ANDROID_CERT, APP_NAME
    )

    assert isinstance(credentials, AppCredentials)
