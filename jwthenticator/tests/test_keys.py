from __future__ import absolute_import

from uuid import uuid4

import pytest

from jwthenticator.keys import KeyManager
from jwthenticator.schemas import KeyData
from jwthenticator.tests.utils import random_key, hash_key, future_datetime


class TestKeys:
    def setup_class(self) -> None:
        self.key_manager = (
            KeyManager()
        )  # pylint: disable=attribute-defined-outside-init

    # Create key tests
    @pytest.mark.asyncio
    async def test_create_key(self) -> None:
        key_a = await random_key()
        assert await self.key_manager.create_key(key_a, uuid4())
        assert await self.key_manager.check_key_exists(await hash_key(key_a))

        key_b = await random_key()
        assert await self.key_manager.create_key(
            key_b, uuid4(), await future_datetime()
        )
        assert await self.key_manager.check_key_exists(await hash_key(key_b))

    # Get key tests
    @pytest.mark.asyncio
    async def test_get_key(self) -> None:
        key_a = await random_key()
        await self.key_manager.create_key(key_a, uuid4())
        key_a_obj = await self.key_manager.get_key(await hash_key(key_a))
        assert isinstance(key_a_obj, KeyData)
