import pytest

from pullkin import Pullkin
from tests.testdata import APP_ID, SENDER_ID


@pytest.mark.asyncio
async def test_aio_login():
    client = Pullkin()
    await client.register(SENDER_ID, APP_ID)

    await client.listen_coroutine()
