from __future__ import absolute_import

from functools import wraps
from typing import Any, Dict, Callable
from urllib.parse import urljoin
from http import HTTPStatus

from aiohttp import ClientSession, web

from jwthenticator.schemas import JWTValidateRequest
from jwthenticator.utils import verify_url, fix_url_path
from jwthenticator.exceptions import InvalidServerURLError, MissingAuthorizationError, BadAuthorizationError, MissingJWTError


def authenticate(jwthenticator_server: str) -> Any:
    """
    Wrapper function to verify user performing the request is authorized.
    The function extracts the JWT token from the header and verifies it against
        an jwthenticator server (given by jwthenticator_server).
    Use it to wrap async endpoints that require authentication.
    :param jwthenticator_server: The (full) URL of the jwthenticator server.
        For example - http://localhost.
    """
    def wrap(func: Callable) -> Any:
        @wraps(func)
        async def async_wrap(request: web.Request, *args: Any, **kwargs: Dict[Any, Any]) -> web.Response:
            # Verify jwthenticator_server is a proper URL
            if not verify_url(jwthenticator_server):
                raise InvalidServerURLError()
            valid_jwthenticator_server = fix_url_path(jwthenticator_server)

            # Extract JWT
            try:
                jwt = await extract_jwt(request)
            except MissingAuthorizationError:
                return web.json_response({}, status=HTTPStatus.FORBIDDEN)
            except BadAuthorizationError:
                return web.json_response({}, status=HTTPStatus.BAD_REQUEST)

            # Verify JWT
            if not await verify_jwt(valid_jwthenticator_server, jwt):
                return web.json_response({}, status=HTTPStatus.UNAUTHORIZED)

            # Verified! Perform actual call
            return await func(request, *args, **kwargs)

        return async_wrap
    return wrap


async def verify_jwt(jwthenticator_server: str, jwt: str) -> bool:
    """
    Verify agains jwthenticator server that the given JWT is valid.
    :return bool: True if valid, False if isn't.
    """
    if not jwthenticator_server.endswith("/"):
        jwthenticator_server = jwthenticator_server + "/"
    url = urljoin(jwthenticator_server, "validate")
    request = JWTValidateRequest(jwt)
    async with ClientSession() as client:
        async with client.post(url, json=JWTValidateRequest.Schema().dump(request)) as response:
            return response.status == HTTPStatus.OK


async def extract_jwt(request: web.Request) -> str:
    """
    Extract JWT from request header.
    :param request: Request to extract JWT header from.
    :return: JWT if exists, raises exception otherwise.
    """
    # Extract authorization header.
    authorization = request.headers.get("Authorization", None)
    if authorization is None:
        raise MissingAuthorizationError

    # Extract JWT from header
    split_authorization = authorization.split(" ")
    if len(split_authorization) != 2 or split_authorization[0] != "Bearer":
        raise BadAuthorizationError

    jwt = split_authorization[1]
    if not jwt:
        raise MissingJWTError
    return jwt
