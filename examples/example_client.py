from __future__ import absolute_import

import asyncio
from uuid import uuid4
from urllib.parse import urljoin
from http import HTTPStatus

from jwthenticator.client import Client, InternalClient

JWTHENTICATOR_HOST = "http://localhost:8080/"
TEST_SERVER_HOST = "http://localhost:8000/"
KEY = "hello-world"


async def main() -> None:
    # Generate identifier that will be used for all requests
    identifier = uuid4()

    # Register a new key to service
    internal_client = InternalClient(JWTHENTICATOR_HOST, identifier)
    await internal_client.register_key(KEY)
    if not await internal_client.is_key_registered(KEY):
        raise Exception("Key failed to register")

    # Create JWThenticator client
    client = Client(JWTHENTICATOR_HOST, identifier, key=KEY)

    # Get secured endpoints
    response = await client.get_with_auth(urljoin(TEST_SERVER_HOST, "/secure"))
    if response.status != HTTPStatus.OK:
        raise Exception("Failed to get authenticated endpoint")


if __name__ == "__main__":
    asyncio.run(main())
