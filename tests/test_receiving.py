import asyncio
from uuid import uuid4

import pytest

from pullkin import AioPullkin
from pullkin.models import Message
from tests.conftest import FirebaseAdmin
from tests.testdata import SENDER_ID


@pytest.mark.asyncio
async def test_aio_receive(fcm: FirebaseAdmin):
    client = AioPullkin()
    fcm_cred = client.register(SENDER_ID)

    @client.on_notification()
    def on_notification(obj, notification: Message, data_message):
        print(notification)

    coroutine = await client.listen_coroutine()

    notification_title = uuid4().hex
    notification_body = uuid4().hex

    fcm.send_notification(fcm_cred.fcm.token, notification_title, notification_body)

    async def wait_notification():
        while not (message := await coroutine.asend(None)):
            await asyncio.sleep(0.5)
        return message

    message: Message = await asyncio.wait_for(wait_notification(), timeout=10)

    message.notification.title == notification_title
    message.notification.body == notification_body
