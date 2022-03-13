import pytest

from pullkin import AioPullkin
from tests.testdata import SENDER_ID


@pytest.mark.asyncio
async def test_aio_login():
    client = AioPullkin()
    client.register(SENDER_ID)

    await client.listen_coroutine()
