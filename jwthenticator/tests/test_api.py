from __future__ import absolute_import

from uuid import uuid4

import pytest

from jwthenticator.api import JWThenticatorAPI
from jwthenticator.schemas import AuthRequest, RefreshRequest, JWTValidateRequest, KeyRequest, RegisterKeyRequest
from jwthenticator.tests.utils import random_key


class TestAPI:

    def setup_class(self) -> None:
        self.api = JWThenticatorAPI() # pylint: disable=attribute-defined-outside-init


    @pytest.mark.asyncio
    async def test_full_flow(self) -> None:
        key = await random_key()
        uuid_identifier = uuid4()

        # Register a new key
        await self.api.register_key(RegisterKeyRequest(key=key, identifier=uuid_identifier))

        # Check that the key was registered
        is_key_registered = await self.api.is_key_registerd(KeyRequest(key=key))
        assert is_key_registered.result

        # Authenticate and get access + refres tokens
        tokens_obj_a = await self.api.authenticate(AuthRequest(key=key, identifier=uuid_identifier))

        # Check access token is valid
        await self.api.validate(JWTValidateRequest(jwt=tokens_obj_a.jwt))

        # Use refresh token to create a new access token
        tokens_obj_b = await self.api.refresh(RefreshRequest(refresh_token=tokens_obj_a.refresh_token, identifier=uuid_identifier)) # type: ignore

        # Check that new access token is also valid
        await self.api.validate(JWTValidateRequest(jwt=tokens_obj_b.jwt))
