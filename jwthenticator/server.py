"""
A web server warpper for JWThenticatorAPI fucntions.
"""
from __future__ import absolute_import

from typing import Optional, Tuple
from http import HTTPStatus
from json.decoder import JSONDecodeError

from aiohttp import web
from marshmallow.exceptions import ValidationError
from jwt.exceptions import InvalidSignatureError, DecodeError

from jwthenticator import schemas, exceptions
from jwthenticator.api import JWThenticatorAPI
from jwthenticator.utils import get_rsa_key_pair
from jwthenticator.server_utils import extract_jwt
from jwthenticator.consts import PORT, URL_PREFIX, DISABLE_EXTERNAL_API, DISABLE_INTERNAL_API


class Server:

    # pylint: disable=too-many-arguments,too-many-instance-attributes
    def __init__(self, rsa_key_pair: Tuple[str, Optional[str]] = get_rsa_key_pair(), start_server: bool = True, port: int = PORT,
                 disable_external_api: bool = DISABLE_EXTERNAL_API, disable_internal_api: bool = DISABLE_INTERNAL_API):
        self.app = web.Application()
        self.api = JWThenticatorAPI(rsa_key_pair)

        self.jwt_validate_request_schema = schemas.JWTValidateRequest.Schema()
        self.bool_response_schema = schemas.BoolResponse.Schema()
        self.jkws_response_schema = schemas.JWKSResponse.Schema()
        self.auth_request_schema = schemas.AuthRequest.Schema()
        self.token_response_schema = schemas.TokenResponse.Schema()
        self.refresh_request_schema = schemas.RefreshRequest.Schema()
        self.key_request_schema = schemas.KeyRequest.Schema()
        self.register_key_request_schema = schemas.RegisterKeyRequest.Schema()

        # Disable certain exposed API functions. This is done to enable separating the service running
        #   between external and internal APIs (for example not to expose key registry externaly)
        if not disable_external_api:
            self.app.add_routes([
                web.post(f"{URL_PREFIX}/authenticate", self.authenticate),
                web.post(f"{URL_PREFIX}/refresh", self.refresh),
                web.post(f"{URL_PREFIX}/validate", self.validate),
                web.get(f"{URL_PREFIX}/validate_request", self.validate_request),
            ])

        if not disable_internal_api:
            self.app.add_routes([
                web.post(f"{URL_PREFIX}/register_key", self.register_key),
                web.post(f"{URL_PREFIX}/is_key_registered", self.is_key_registered),
            ])

        # General access routes
        self.app.add_routes([
            web.get(f"{URL_PREFIX}/", self.check_health),
            web.get(f"{URL_PREFIX}/health", self.check_health),
            web.get(f"{URL_PREFIX}/jwks", self.jwks),
        ])

        if start_server:
            web.run_app(self.app, port=port)


    async def authenticate(self, request: web.Request) -> web.Response:
        """
        :param request: AuthRequest
        :return: TokenResponse is successfull, BoleanResponse if not.
        """
        try:
            data = await request.json()
            authenticate_request = self.auth_request_schema.load(data)
            result = await self.api.authenticate(authenticate_request)
            return web.json_response(self.token_response_schema.dump(result), status=HTTPStatus.OK)
        except JSONDecodeError:
            return web.json_response({}, status=HTTPStatus.BAD_REQUEST)
        except ValidationError as err:
            return web.json_response(err.messages, status=HTTPStatus.BAD_REQUEST)
        except (exceptions.InvalidKeyError, exceptions.ExpiredError):
            return web.json_response({}, status=HTTPStatus.UNAUTHORIZED)


    async def refresh(self, request: web.Request) -> web.Response:
        """
        :param request: RefreshRequest
        :return: TokenResponse
        """
        try:
            data = await request.json()
            refresh_request = self.refresh_request_schema.load(data)
            result = await self.api.refresh(refresh_request)
            return web.json_response(self.token_response_schema.dump(result), status=HTTPStatus.OK)
        except JSONDecodeError:
            return web.json_response({}, status=HTTPStatus.BAD_REQUEST)
        except ValidationError as err:
            return web.json_response(err.messages, status=HTTPStatus.BAD_REQUEST)
        except (exceptions.InvalidTokenError, exceptions.ExpiredError):
            return web.json_response({}, status=HTTPStatus.UNAUTHORIZED)


    async def validate(self, request: web.Request) -> web.Response:
        """
        Validate a JWT (access) token.
        :param request: JWTValidateRequest
        :return: BoolResponse
        """
        try:
            data = await request.json()
            validate_request = self.jwt_validate_request_schema.load(data)
            result = await self.api.validate(validate_request)
            return web.json_response(self.bool_response_schema.dump(result), status=HTTPStatus.OK)
        except JSONDecodeError:
            return web.json_response({}, status=HTTPStatus.BAD_REQUEST)
        except ValidationError as err:
            return web.json_response(err.messages, status=HTTPStatus.BAD_REQUEST)
        except (InvalidSignatureError, DecodeError, exceptions.ExpiredError):
            return web.json_response({}, status=HTTPStatus.UNAUTHORIZED)


    async def validate_request(self, request: web.Request) -> web.Response:
        """
        Endpoint receives an empty request with authentication header,
            extracts JWT and validates it.
        This endpoint can be used with as an Nginx auth_request handler.
        :param request: Empty request (hopefully with authentication header)
        """
        try:
            jwt = await extract_jwt(request)
            validate_request = schemas.JWTValidateRequest(jwt)
            result = await self.api.validate(validate_request)
            if result.result:
                return web.json_response({}, status=HTTPStatus.OK)
            return web.json_response({}, status=HTTPStatus.UNAUTHORIZED)
        except (exceptions.MissingAuthorizationError, exceptions.BadAuthorizationError, exceptions.MissingJWTError):
            return web.json_response({}, status=HTTPStatus.FORBIDDEN)
        except exceptions.ExpiredError:
            return web.json_response({}, status=HTTPStatus.UNAUTHORIZED)


    async def register_key(self, request: web.Request) -> web.Response:
        """
        :param request: KeyRequest
        :return: BoolResponse
        """
        try:
            data = await request.json()
            key_request = self.register_key_request_schema.load(data)
            result = await self.api.register_key(key_request)
            return web.json_response(self.bool_response_schema.dump(result), status=HTTPStatus.CREATED)
        except JSONDecodeError:
            return web.json_response({}, status=HTTPStatus.BAD_REQUEST)
        except ValidationError as err:
            return web.json_response(err.messages, status=HTTPStatus.BAD_REQUEST)


    async def is_key_registered(self, request: web.Request) -> web.Response:
        """
        :param request: KeyRequest
        :return: BoolResponse
        """
        try:
            data = await request.json()
            key_request = self.key_request_schema.load(data)
            result = await self.api.is_key_registerd(key_request)
            return web.json_response(self.bool_response_schema.dump(result), status=HTTPStatus.OK)
        except JSONDecodeError:
            return web.json_response({}, status=HTTPStatus.BAD_REQUEST)
        except ValidationError as err:
            return web.json_response(err.messages, status=HTTPStatus.BAD_REQUEST)


    async def jwks(self, _request: web.Request) -> web.Response:
        """
        :return: JWKSResponse
        """
        result = await self.api.get_jwks()
        return web.json_response(self.jkws_response_schema.dump(result), status=HTTPStatus.OK)


    async def check_health(self, _request: web.Request) -> web.Response:
        """
        Health check method for the server, used to check if server is up and serving.
        :return: BoolResponse
        """
        result = schemas.BoolResponse(result=True)
        return web.json_response(self.bool_response_schema.dump(result), status=HTTPStatus.OK)


if __name__ == "__main__":
    Server()
