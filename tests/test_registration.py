import pytest

from pullkin import AioPullkin, Pullkin


@pytest.mark.asyncio
async def test_aio_registration():
    client = AioPullkin()
    credentials = client.register(581003993230)


def test_registration():
    client = Pullkin()
    credentials = client.register(581003993230)
