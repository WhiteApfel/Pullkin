import asyncio
from uuid import uuid4

import pytest

from pullkin import Pullkin
from pullkin.models import Message
from tests.conftest import FirebaseAdmin
from tests.testdata import (
    ANDROID_CERT,
    API_KEY,
    APP_ID,
    APP_NAME,
    FIREBASE_NAME,
    SENDER_ID,
)


@pytest.mark.asyncio
async def test_aio_receive(fcm: FirebaseAdmin):
    client = Pullkin()
    fcm_cred = await client.register(SENDER_ID, APP_ID, API_KEY, FIREBASE_NAME)

    await client.add_app(SENDER_ID, fcm_cred, [])
    coroutine = await client.listen_coroutine(SENDER_ID)

    notification_title = uuid4().hex
    notification_body = uuid4().hex

    fcm.send_notification(fcm_cred.fcm.token, notification_title, notification_body)

    async def wait_notification():
        while not (message := await coroutine.asend(None)):
            await asyncio.sleep(0.5)
        return message

    message: Message = await asyncio.wait_for(wait_notification(), timeout=15)

    assert message.notification.title == notification_title
    assert message.notification.body == notification_body
