from dataclasses import is_dataclass

import pytest

from pullkin import Pullkin
from tests.testdata import APP_ID, SENDER_ID


@pytest.mark.asyncio
async def test_aio_registration():
    client = Pullkin()
    credentials = await client.register(SENDER_ID, APP_ID)

    assert is_dataclass(credentials)
