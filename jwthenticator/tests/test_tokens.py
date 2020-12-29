from __future__ import absolute_import

from uuid import uuid4

import pytest

from jwthenticator.tokens import TokenManager
from jwthenticator.keys import KeyManager
from jwthenticator.utils import create_rsa_key_pair
from jwthenticator.schemas import RefreshTokenData
from jwthenticator.tests.utils import random_key, hash_key


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
    async def test_create_access_token(self) -> None:
        uuid = uuid4()
        token = await self.token_manager.create_access_token(uuid)
        token_data = await self.token_manager.load_access_token(token)
        assert token_data.identifier == uuid


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
