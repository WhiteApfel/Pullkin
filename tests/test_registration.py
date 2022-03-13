from dataclasses import is_dataclass

import pytest

from pullkin import AioPullkin, Pullkin
from tests.testdata import SENDER_ID


@pytest.mark.asyncio
async def test_aio_registration():
    client = AioPullkin()
    credentials = client.register(SENDER_ID)

    assert is_dataclass(credentials)


def test_registration():
    client = Pullkin()
    credentials = client.register(SENDER_ID)

    assert is_dataclass(credentials)
