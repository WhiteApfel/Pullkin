import pytest

from pullkin import Pullkin
from tests.testdata import (
    ANDROID_CERT,
    API_KEY,
    APP_ID,
    APP_NAME,
    FIREBASE_NAME,
    SENDER_ID,
)


@pytest.mark.asyncio
async def test_aio_login():
    client = Pullkin()
    await client.register(
        SENDER_ID, APP_ID, API_KEY, ANDROID_CERT, FIREBASE_NAME, APP_NAME
    )

    await client.listen_coroutine()
