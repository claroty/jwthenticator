# pylint: disable=too-few-public-methods
from __future__ import absolute_import

import inspect
from os.path import basename
from uuid import uuid4
from http import HTTPStatus
from typing import Union
from unittest.mock import patch

from aiohttp import web, ClientSession
from aiohttp.client import ClientSession as ClientSessionType
from aiohttp.test_utils import AioHTTPTestCase, TestClient

from jwthenticator.server import Server
from jwthenticator.client import Client, InternalClient
from jwthenticator.server_utils import authenticate
from jwthenticator.tests.utils import random_key

SERVER_PORT = 8090
SERVER_HOST = "127.0.0.1"
SERVER_URL = f"http://{SERVER_HOST}:{SERVER_PORT}"
CLIENT_PATCH_FILES = ["client.py"]


@authenticate(SERVER_URL)
async def secure_endpoint(request: web.Request) -> web.Response:    # pylint: disable=unused-argument
    return web.json_response({}, status=HTTPStatus.OK)


class ContextAwareClient:
    """
    A "context aware" client get function to allow selective
        `async with ClientSession()...` patching.
    __call__ checks what file is being patched and patches client selectively.
    """
    def __init__(self, test_client: TestClient):
        self.test_client = test_client

    async def __call__(self) -> Union[TestClient, ClientSessionType]:
        context = inspect.stack()
        caller_file = basename(context[1].filename)
        if caller_file in CLIENT_PATCH_FILES:
            return self.test_client
        return ClientSession()


class TestIntegration(AioHTTPTestCase):
    """
    Test all of JWThenticator components.
    Tests raises an JWThenticator server, and then tests teh communication
        between a jwthenticator client to an jwthenticator protected server.
    """

    async def get_application(self) -> web.Application:
        server = Server(start_server=False)
        server.app.add_routes([web.get("/dummy", secure_endpoint)])
        return server.app

    async def setUpAsync(self) -> None:
        self.app = await self.get_application()
        self.server = await self.get_server(self.app)
        self.server.port = SERVER_PORT
        self.client = await self.get_client(self.server)

        await self.client.start_server()

    async def test_client_and_authenticated_server(self) -> None:
        key = await random_key()
        uuid_identifier = uuid4()

        # Register key with internal client
        internal_client = InternalClient(SERVER_URL, uuid_identifier)
        await internal_client.register_key(key)
        assert await internal_client.is_key_registered(key)

        # Create jwthenticator client
        client = Client(SERVER_URL, uuid_identifier, key=key)
        # Test refresh
        await client.refresh()
        # Test get_with_auth
        with patch("aiohttp.ClientSession.__aenter__", ContextAwareClient(self.client)):
            response = await client.get_with_auth("/dummy")
            assert response.status == HTTPStatus.OK

        # Test client with JWT and see that doesn't try to refresh (will fail if tries)
        client2 = Client(SERVER_URL, uuid_identifier, jwt=client.jwt)
        with patch("aiohttp.ClientSession.__aenter__", ContextAwareClient(self.client)):
            response = await client2.get_with_auth("/dummy")
            assert response.status == HTTPStatus.OK
