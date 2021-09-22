from __future__ import absolute_import

from typing import Optional, Any, Dict
from datetime import datetime
from urllib.parse import urljoin
from http import HTTPStatus
from uuid import UUID

import jwt as pyjwt # To avoid redfinition in class
from aiohttp import ClientSession, ClientResponse

from jwthenticator import schemas, exceptions
from jwthenticator.utils import verify_url, fix_url_path
from jwthenticator.consts import JWT_ALGORITHM

JWT_DECODE_OPTIONS = {"verify_signature": False, "verify_exp": False}


# pylint: disable=too-many-instance-attributes
class Client:
    """
    Class provides state management for working with JWThenticator.
    Exporting wrapper functions for "no brainer" usage against JWThenticator.
    All functions in this class are async.
    """

    # pylint: disable=too-many-arguments
    def __init__(self, jwthenticator_server: str, identifier: UUID, jwt: Optional[str] = None,
                 refresh_token: Optional[str] = None, key: Optional[str] = None,
                 verify_ssl: Optional[bool] = None, algorithm: str = JWT_ALGORITHM) -> None:
        """
        :param jwthenticator_server: The (full) URL of the jwthenticator server.
            For example - http://localhost:8080/.
        :param identifier: The UUID identifier that will be used for all operations against
            jwthenticator server.
        :param jwt: JWT (if you already have one previsioned).
        :param refresh_token: Refresh token (if you already have one previsioned).
        :param key: Key to used to authenticate against jwthenticator server.
        :param verify_ssl: The SSL validation mode given to aiohttp client. Use None for default
            one or False to disable certificate check.
        :param algorithm: The JWT algorithm used. This is needed for decoding received JWTs
            and extracting their expiry time. If not given, default will be used.
        """
        self.jwthenticator_server = jwthenticator_server
        self.identifier = identifier
        self.verify_ssl = verify_ssl
        self.algorithm = algorithm

        self._jwt_exp = None
        self.jwt = jwt
        self._refresh_token = refresh_token
        self._key = key

        # Verify jwthenticator_server is a proper URL
        if not verify_url(self.jwthenticator_server):
            raise exceptions.InvalidServerURLError()
        self.jwthenticator_server = fix_url_path(self.jwthenticator_server)

        # Verify at least one of these was given.
        if self.jwt is None and self._refresh_token is None and self._key is None:
            raise exceptions.MissingCredentialsError()

        self.auth_request_schema = schemas.AuthRequest.Schema()
        self.refresh_request_schema = schemas.RefreshRequest.Schema()
        self.token_response_schema = schemas.TokenResponse.Schema()


    @property
    def jwt(self) -> Optional[str]:
        return self._jwt

    @jwt.setter
    def jwt(self, value: str) -> None:
        self._jwt = value
        if value:
            # Algorithm is given (even though the client doesn't care) since it's required by pyjwt.
            self._jwt_exp = pyjwt.decode(value, options=JWT_DECODE_OPTIONS, algorithms=[self.algorithm]).get("exp")
        else:
            self._jwt_exp = None

    @property
    def is_jwt_expired(self) -> bool:
        if self._jwt_exp is None:
            return True
        return datetime.now().timestamp() >= self._jwt_exp

    @property
    def refresh_token(self) -> Optional[str]:
        return self._refresh_token

    @property
    def header(self) -> Dict[str, str]:
        """
        Get requests style header with JWT.
        """
        return {"Authorization": f"Bearer {self.jwt}"}


    async def refresh(self, auth_on_fail: bool = True) -> None:
        """
        Perfrom "refresh" request.
        :param auth_on_fail: Whether to try and authenticate if refreshing fails.
        :return: None or raises exception if fails.
        """
        if self._refresh_token is None:
            return await self.authenticate()

        url = urljoin(self.jwthenticator_server, "refresh")
        request = schemas.RefreshRequest(self._refresh_token, self.identifier)
        async with ClientSession() as client:
            async with client.post(url, json=self.refresh_request_schema.dump(request), ssl=self.verify_ssl) as response:

                if response.status != HTTPStatus.OK:
                    if response.status == HTTPStatus.UNAUTHORIZED:
                        self._refresh_token = None
                    if auth_on_fail:
                        return await self.authenticate()
                    raise exceptions.RefreshError()

                token_response_data = await response.json()

        result = self.token_response_schema.load(token_response_data)
        self.jwt = result.jwt


    async def authenticate(self) -> None:
        """
        Perform "authenticate" request.
        :return: None or raises exception if fails.
        """
        if self._key is None:
            raise Exception("Missing key")

        url = urljoin(self.jwthenticator_server, "authenticate")
        request = schemas.AuthRequest(self._key, self.identifier)
        async with ClientSession() as client:
            async with client.post(url, json=self.auth_request_schema.dump(request), ssl=self.verify_ssl) as response:

                if response.status != HTTPStatus.OK:
                    if response.status == HTTPStatus.UNAUTHORIZED:
                        self._key = None
                    raise exceptions.AuthenticationError()

                token_response_data = await response.json()

        result = self.token_response_schema.load(token_response_data)
        self.jwt = result.jwt
        self._refresh_token = result.refresh_token if result.refresh_token else self._refresh_token


    async def _make_request(self, method: str, url: str, **kwargs: Dict[str, Any]) -> ClientResponse:
        """
        Add auth headers and make actually make the request.
        """
        headers = kwargs.get("headers", {})
        headers.update(self.header)
        kwargs["headers"] = headers
        async with ClientSession() as client:
            response = await client.request(method, url, ssl=self.verify_ssl, **kwargs)
        return response


    async def request_with_auth(self, method: str, url: str, **kwargs: Dict[str, Any]) -> ClientResponse:
        """
        Perform request with authentication headers.
        """
        # Refresh if JWT is expired or doesn't exist, done to minimize number of requests to server.
        if self.is_jwt_expired or self.jwt is None:
            await self.refresh()

        # Try to make request
        response = await self._make_request(method, url, **kwargs)

        # If receive unauthorized, try to refresh once more (possibly expired or invalid JWT).
        if response.status == HTTPStatus.UNAUTHORIZED:
            self.jwt = None
            await self.refresh()
            response = await self._make_request(method, url, **kwargs)

        return response


    async def get_with_auth(self, url: str, **kwargs: Dict[str, Any]) -> ClientResponse:
        """
        Perform get request with JWT header.
        """
        return await self.request_with_auth("GET", url, **kwargs)


    async def post_with_auth(self, url: str, **kwargs: Dict[str, Any]) -> ClientResponse:
        """
        Perform post request with JWT header.
        """
        return await self.request_with_auth("POST", url, **kwargs)



class InternalClient:
    """
    Class provides easier calling to the JWThenticator's "internal" functionality.
    All function in this class are async.
    """

    def __init__(self, jwthenticator_server: str, identifier: UUID, verify_ssl: Optional[bool] = None) -> None:
        """
        :param jwthenticator_server: The (full) URL of the jwthenticator server.
            For example - http://localhost:8080/.
        :param identifier: The UUID identifier that will be used for all operations against
            jwthenticator server.
        :param verify_ssl: The SSL validation mode given to aiohttp client. Use None for default
            one or False to disable certificate check.
        """
        self.jwthenticator_server = jwthenticator_server
        self.identifier = identifier
        self.verify_ssl = verify_ssl

        # Verify jwthenticator_server is a proper URL
        if not verify_url(self.jwthenticator_server):
            raise exceptions.InvalidServerURLError()
        self.jwthenticator_server = fix_url_path(self.jwthenticator_server)

        self.register_key_request_schema = schemas.RegisterKeyRequest.Schema()
        self.key_request_schema = schemas.KeyRequest.Schema()
        self.bool_response_schema = schemas.BoolResponse.Schema()


    async def register_key(self, key: str) -> None:
        """
        Register a key to the jwthenticator server.
        :param key: The key to register.
        :return: None or raises exception if fails.
        """
        url = urljoin(self.jwthenticator_server, "register_key")
        request = schemas.RegisterKeyRequest(key, self.identifier)
        async with ClientSession() as client:
            async with client.post(url, json=self.register_key_request_schema.dump(request), ssl=self.verify_ssl) as response:

                if response.status != HTTPStatus.CREATED:
                    raise exceptions.RegisterKeyError(response.status)

                bool_response_data = await response.json()

        result = self.bool_response_schema.load(bool_response_data)
        if not result.result:
            raise exceptions.RegisterKeyError(result.message)


    async def is_key_registered(self, key: str) -> bool:
        """
        Check if a key is already registered in the jwthenticator server.
        :param key: The key to check if registered.
        :return: None or raises exception if fails.
        """
        url = urljoin(self.jwthenticator_server, "is_key_registered")
        request = schemas.KeyRequest(key)
        async with ClientSession() as client:
            async with client.post(url, json=self.key_request_schema.dump(request), ssl=self.verify_ssl) as response:

                if response.status != HTTPStatus.OK:
                    raise exceptions.IsKeyRegisteredError(response.status)

                bool_response_data = await response.json()

        result = self.bool_response_schema.load(bool_response_data)
        return result.result
