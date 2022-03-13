import pytest

from pullkin import AioPullkin, Pullkin
from tests.testdata import SENDER_ID


@pytest.mark.asyncio
async def test_aio_login():
    client = AioPullkin()
    fcm_cred = client.register(SENDER_ID)

    await client.listen_coroutine()
