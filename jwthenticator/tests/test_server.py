# pylint: disable=attribute-defined-outside-init
from __future__ import absolute_import

from uuid import uuid4
from http import HTTPStatus
from unittest.mock import MagicMock

from aiohttp.test_utils import AioHTTPTestCase
from aiohttp.web import Application
from jwt import PyJWKClient

from freezegun import freeze_time

from jwthenticator.server import Server
from jwthenticator.schemas import AuthRequest, RefreshRequest, JWTValidateRequest, KeyRequest, TokenResponse, RegisterKeyRequest
from jwthenticator.consts import JWT_LEASE_TIME, KEY_EXPIRY, REFRESH_TOKEN_EXPIRY
from jwthenticator.tests.utils import random_key, sync_random_key, random_refresh_token, future_datetime

POST_ROUTES = ["/authenticate", "/refresh", "/validate", "/register_key", "/is_key_registered"]


# pylint: disable=too-many-public-methods,too-many-instance-attributes
class TestServer(AioHTTPTestCase):
    """
    Based on AioHTTPTestCase that does some weird voodoo magic.
    See https://docs.aiohttp.org/en/stable/testing.html#unittest
    """

    async def get_application(self) -> Application:
        """
        Override AioHTTPTestCase get_application func.
        """
        self.api_server = Server(start_server=False)
        self.app = self.api_server.app
        return self.app


    def setup_class(self) -> None:
        self.auth_request_schema = AuthRequest.Schema()
        self.token_response_schema = TokenResponse.Schema()
        self.refresh_request_schema = RefreshRequest.Schema()
        self.jwt_validate_request_schema = JWTValidateRequest.Schema()
        self.key_request_schema = KeyRequest.Schema()
        self.register_key_request_schema = RegisterKeyRequest.Schema()


    # Util functions
    async def register_key(self, key: str = sync_random_key()) -> str:
        request = RegisterKeyRequest(key, uuid4())
        response = await self.client.post("/register_key", json=self.register_key_request_schema.dump(request))
        assert response.status == HTTPStatus.CREATED
        return key

    async def perform_auth(self) -> TokenResponse:
        key = await self.register_key()
        request = self.auth_request_schema.dump(AuthRequest(key=key, identifier=uuid4()))
        response = await self.client.post("/authenticate", json=request)
        return self.token_response_schema.load(await response.json())


    # Sanity Tests
    async def test_full_flow(self) -> None:
        key = await random_key()
        uuid_identifier = uuid4()

        # Register a new key
        # This is done using direct json since KeyRequest.dump doesn't dump key (on purpose)
        request = RegisterKeyRequest(key, uuid4())
        response = await self.client.post("/register_key", json=self.register_key_request_schema.dump(request))
        assert response.status == HTTPStatus.CREATED

        # Check that the key was registered
        request2 = KeyRequest(key)
        response = await self.client.post("/is_key_registered", json=self.key_request_schema.dump(request2))
        assert response.status == HTTPStatus.OK

        # Authenticate and get access + refres tokens
        request = self.auth_request_schema.dump(AuthRequest(key=key, identifier=uuid_identifier))
        response = await self.client.post("/authenticate", json=request)
        assert response.status == HTTPStatus.OK
        response_json = await response.json()

        # Check access token is valid
        request = self.jwt_validate_request_schema.dump(JWTValidateRequest(jwt=response_json["jwt"]))
        response = await self.client.post("/validate", json=request)
        assert response.status == HTTPStatus.OK

        # Use refresh token to create a new access token
        request = self.refresh_request_schema.dump(RefreshRequest(refresh_token=response_json["refresh_token"], identifier=uuid_identifier))
        response = await self.client.post("/refresh", json=request)
        assert response.status == HTTPStatus.OK
        response_json = await response.json()

        # Check that new access token is also valid
        token = response_json["jwt"]
        request = self.jwt_validate_request_schema.dump(JWTValidateRequest(jwt=token))
        response = await self.client.post("/validate", json=request)
        assert response.status == HTTPStatus.OK

        # Test JWKS
        response = await self.client.get("/jwks")
        assert response.status == HTTPStatus.OK
        response_json = await response.json()
        jwks_client = PyJWKClient("")
        jwks_client.fetch_data = MagicMock(return_value=response_json)  # type: ignore
        assert jwks_client.get_signing_key_from_jwt(token)


    async def test_bad_json_request(self) -> None:
        for route in POST_ROUTES:
            response = await self.client.post(route, json="{")
            assert response.status == HTTPStatus.BAD_REQUEST

    # Authenticate Tests
    async def test_authentication_bad_request(self) -> None:
        # Missing field
        request = {"key": await random_key()}
        response = await self.client.post("/authenticate", json=request)
        assert response.status == HTTPStatus.BAD_REQUEST

        # Extra (unknown) field
        request = {"key": await random_key(), "identifier": uuid4().hex, "extra": "extra"}
        response = await self.client.post("/authenticate", json=request)
        assert response.status == HTTPStatus.BAD_REQUEST

    async def test_authentication_unknown_key(self) -> None:
        request = self.auth_request_schema.dump(AuthRequest(key=await random_key(), identifier=uuid4()))
        response = await self.client.post("/authenticate", json=request)
        assert response.status == HTTPStatus.UNAUTHORIZED

    async def test_authentication_expired_key(self) -> None:
        key = await self.register_key()
        request = self.auth_request_schema.dump(AuthRequest(key=key, identifier=uuid4()))
        future_date = await future_datetime(KEY_EXPIRY + 1)
        with freeze_time(lambda: future_date):
            response = await self.client.post("/authenticate", json=request)
            assert response.status == HTTPStatus.UNAUTHORIZED

    # Refresh Tests
    async def test_refresh_bad_request(self) -> None:
        # Missing field
        request = {"refresh_token": await random_refresh_token()}
        response = await self.client.post("/refresh", json=request)
        assert response.status == HTTPStatus.BAD_REQUEST

        # Extra (unknown) field
        request = {"refresh_token": await random_refresh_token(), "identifier": uuid4().hex, "extra": "extra"}
        response = await self.client.post("/refresh", json=request)
        assert response.status == HTTPStatus.BAD_REQUEST

    async def test_refresh_unknown_refresh_token(self) -> None:
        request = self.refresh_request_schema.dump(RefreshRequest(refresh_token=await random_refresh_token(), identifier=uuid4()))
        response = await self.client.post("/refresh", json=request)
        assert response.status == HTTPStatus.UNAUTHORIZED

    async def test_refresh_expired_refresh_token(self) -> None:
        token_response_obj = await self.perform_auth()
        request = self.refresh_request_schema.dump(RefreshRequest(refresh_token=token_response_obj.refresh_token, identifier=uuid4()))  # type: ignore

        future_date = await future_datetime(REFRESH_TOKEN_EXPIRY + 1)
        with freeze_time(lambda: future_date):
            response = await self.client.post("/refresh", json=request)
            assert response.status == HTTPStatus.UNAUTHORIZED

    # Validate Tests
    async def test_validate_bad_request(self) -> None:
        # Missing field
        response = await self.client.post("/validate", json={})
        assert response.status == HTTPStatus.BAD_REQUEST

        # Extra (unknown) field
        request = {"jwt": "hello_world", "extra": "extra"}
        response = await self.client.post("/validate", json=request)
        assert response.status == HTTPStatus.BAD_REQUEST

    async def test_validate_bad_jwt(self) -> None:
        token_response_obj = await self.perform_auth()
        request = self.jwt_validate_request_schema.dump(JWTValidateRequest(jwt=token_response_obj.jwt[:-2]))
        response = await self.client.post("/validate", json=request)
        assert response.status == HTTPStatus.UNAUTHORIZED

        request = self.jwt_validate_request_schema.dump(JWTValidateRequest(jwt=token_response_obj.jwt[2:]))
        response = await self.client.post("/validate", json=request)
        assert response.status == HTTPStatus.UNAUTHORIZED

    async def test_validate_expired_jwt(self) -> None:
        token_response_obj = await self.perform_auth()
        request = self.jwt_validate_request_schema.dump(JWTValidateRequest(jwt=token_response_obj.jwt))

        future_date = await future_datetime(JWT_LEASE_TIME + 1)
        with freeze_time(lambda: future_date):
            response = await self.client.post("/validate", json=request)
            assert response.status == HTTPStatus.UNAUTHORIZED


    # Register Key Tests
    async def test_register_key_bad_request(self) -> None:
        # Missing field
        response = await self.client.post("/register_key", json={})
        assert response.status == HTTPStatus.BAD_REQUEST

        # Extra (unknown) field
        request = {"key": await random_key(), "extra": "extra"}
        response = await self.client.post("/register_key", json=request)
        assert response.status == HTTPStatus.BAD_REQUEST

    async def test_register_key_already_registered(self) -> None:
        # Already registered (and still valid) key
        key = await self.register_key()
        request = RegisterKeyRequest(key, uuid4())
        response = await self.client.post("/register_key", json=self.register_key_request_schema.dump(request))
        assert response.status == HTTPStatus.CREATED

        # Registered and expired
        future_date = await future_datetime(KEY_EXPIRY + 1)
        with freeze_time(lambda: future_date):
            response = await self.client.post("/register_key", json=self.register_key_request_schema.dump(request))
            assert response.status == HTTPStatus.CREATED


    # Is Key Registered Tests
    async def test_is_key_registered_bad_request(self) -> None:
        # Missing field
        response = await self.client.post("/is_key_registered", json={})
        assert response.status == HTTPStatus.BAD_REQUEST

        # Extra (unknown) field
        request = {"key": await random_key(), "extra": "extra"}
        response = await self.client.post("/is_key_registered", json=request)
        assert response.status == HTTPStatus.BAD_REQUEST


    # Validate request tests
    async def test_validate_request(self) -> None:
        token_response_obj = await self.perform_auth()
        headers = {"Authorization": f"Bearer {token_response_obj.jwt}"}
        response = await self.client.get("/validate_request", headers=headers)
        assert response.status == HTTPStatus.OK

    async def test_validate_request_expired_token(self) -> None:
        token_response_obj = await self.perform_auth()
        headers = {"Authorization": f"Bearer {token_response_obj.jwt}"}

        future_date = await future_datetime(JWT_LEASE_TIME + 1)
        with freeze_time(lambda: future_date):
            response = await self.client.get("/validate_request", headers=headers)
            assert response.status == HTTPStatus.UNAUTHORIZED

    async def test_validate_request_bad_header(self) -> None:
        # No Authorization header
        response = await self.client.get("/validate_request")
        assert response.status == HTTPStatus.FORBIDDEN

        # Bad Authorization header
        headers = {"Authorization": "Bearer "}
        response = await self.client.get("/validate_request", headers=headers)
        assert response.status == HTTPStatus.FORBIDDEN



class TestExternalOnlyServer(AioHTTPTestCase):

    async def get_application(self) -> Application:
        """
        Override AioHTTPTestCase get_application func.
        """
        self.api_server = Server(start_server=False, disable_internal_api=True)
        self.app = self.api_server.app
        return self.app

    async def test_external_api_sanity(self) -> None:
        response = await self.client.post("/validate", json={})
        assert response.status == HTTPStatus.BAD_REQUEST

    async def test_disabled_internal_api(self) -> None:
        response = await self.client.post("/register_key", json={})
        assert response.status == HTTPStatus.NOT_FOUND

        response = await self.client.post("/is_key_registered", json={})
        assert response.status == HTTPStatus.NOT_FOUND



class TestInternalOnlyServer(AioHTTPTestCase):

    async def get_application(self) -> Application:
        """
        Override AioHTTPTestCase get_application func.
        """
        self.api_server = Server(start_server=False, disable_external_api=True)
        self.app = self.api_server.app
        return self.app

    async def test_internal_api_sanity(self) -> None:
        response = await self.client.post("/register_key", json={})
        assert response.status == HTTPStatus.BAD_REQUEST

    async def test_disabled_external_api(self) -> None:
        response = await self.client.post("/authenticate", json={})
        assert response.status == HTTPStatus.NOT_FOUND

        response = await self.client.post("/refresh", json={})
        assert response.status == HTTPStatus.NOT_FOUND

        response = await self.client.post("/validate", json={})
        assert response.status == HTTPStatus.NOT_FOUND

    async def test_health_check(self) -> None:
        response = await self.client.get("/health")
        assert response.status == HTTPStatus.OK
