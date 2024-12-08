from __future__ import absolute_import

import time
import os
from datetime import timedelta
from collections.abc import Callable, Generator
from uuid import uuid4

import pytest

from jwthenticator.tokens import TokenManager
from jwthenticator.keys import KeyManager
from jwthenticator.utils import create_rsa_key_pair, utcnow
from jwthenticator.schemas import RefreshTokenData
from jwthenticator.tests.utils import random_key, hash_key


@pytest.fixture
def set_timezone()-> Generator[Callable[[str], None], None, None]:
    original_tz = os.environ.get('TZ')
    def change_timezone(time_zone: str) -> None:
        os.environ['TZ'] = time_zone
        time.tzset()  # Update the timezone for the process
    yield change_timezone
    # Restore the original timezone
    if original_tz is not None:
        os.environ['TZ'] = original_tz
    else:
        del os.environ['TZ']
    time.tzset()

class TestTokens:

    def setup_class(self) -> None:
        public_key, private_key = create_rsa_key_pair()
        self.token_manager = TokenManager(public_key, private_key) # pylint: disable=attribute-defined-outside-init
        self.key_manager = KeyManager() # pylint: disable=attribute-defined-outside-init


    async def _create_random_key(self) -> int:
        """
        Create a random key in database.
        :return: It's id.
        """
        key = await random_key()
        await self.key_manager.create_key(key, uuid4())
        key_obj = await self.key_manager.get_key(await hash_key(key))
        return key_obj.id


    async def _create_refresh_token(self) -> str:
        """
        Create a refresh token.
        :return: The refresh token.
        """
        key_id = await self._create_random_key()
        refresh_token = await self.token_manager.create_refresh_token(key_id)
        return refresh_token


    # Create access token tests
    @pytest.mark.asyncio
    async def test_create_access_token(self, set_timezone: Callable[[str], None]) -> None: # pylint: disable=redefined-outer-name
        uuid = uuid4()
        time_now = utcnow()
        time_now_timestamp = int(time_now.timestamp())
        time_plus_some_time = time_now + timedelta(seconds=10)
        time_plus_some_time_timestamp = int(time_plus_some_time.timestamp())
        set_timezone("America/Los_Angeles")
        token = await self.token_manager.create_access_token(uuid)
        token_data = await self.token_manager.load_access_token(token)
        assert token_data.identifier == uuid
        assert time_now_timestamp <= token_data.iat <= time_plus_some_time_timestamp

    # Create refresh token tests
    @pytest.mark.asyncio
    async def test_create_refresh_token(self) -> None:
        key_id = await self._create_random_key()
        refresh_token = await self.token_manager.create_refresh_token(key_id)
        assert await self.token_manager.check_refresh_token_exists(refresh_token)


    # Load refresh token tests
    @pytest.mark.asyncio
    async def test_load_refresh_token(self) -> None:
        refresh_token = await self._create_refresh_token()
        refresh_token_obj = await self.token_manager.load_refresh_token(refresh_token)
        assert isinstance(refresh_token_obj, RefreshTokenData)
