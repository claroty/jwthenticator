from __future__ import absolute_import

from typing import Optional, Tuple
from hashlib import sha512

from Cryptodome.PublicKey import RSA
from jwt.utils import force_unicode, to_base64url_uint

from jwthenticator import schemas
from jwthenticator.tokens import TokenManager
from jwthenticator.keys import KeyManager
from jwthenticator.consts import JWT_ALGORITHM, JWT_ALGORITHM_FAMILY, JWT_LEASE_TIME, JWT_AUDIENCE
from jwthenticator.utils import get_rsa_key_pair
from jwthenticator.exceptions import ExpiredError

INT_TO_BIG_ENDIAN = lambda x: force_unicode(to_base64url_uint(x))


class JWThenticatorAPI:
    """
    High level authentication API functions.
    Class uses TokenManager + KeyManager and provides API logic using them.
    """

    # pylint: disable=too-many-arguments
    def __init__(self, rsa_key_pair: Tuple[str, Optional[str]] = get_rsa_key_pair(),
                 jwt_lease_time: int = JWT_LEASE_TIME, jwt_algorithm: str = JWT_ALGORITHM,
                 jwt_algorithm_family: str = JWT_ALGORITHM_FAMILY, jwt_audience: Optional[str] = JWT_AUDIENCE):
        """
        Class can be initiated without giving any parameter, will generate RSA key pair by itself.
        :param rsa_key_pair: (public_key, private_key) RSA key pair. Will generate keys if not given
            keys or paths through consts. In canse private_key is None will only support token validation.
        """
        self.public_key, self._private_key = rsa_key_pair
        self.jwt_algorithm = jwt_algorithm
        self.jwt_algorithm_family = jwt_algorithm_family

        self.token_manager = TokenManager(self.public_key, self._private_key, self.jwt_algorithm, jwt_lease_time, jwt_audience)
        self.key_manager = KeyManager()


    async def authenticate(self, request: schemas.AuthRequest) -> schemas.TokenResponse:
        """
        Authenticate using a key.
        :return: access + refresh tokens if successfull
        """
        key_hash = sha512(request.key.encode()).hexdigest()
        key_obj = await self.key_manager.get_key(key_hash)
        if not await key_obj.is_valid():
            raise ExpiredError("Key is expired.")

        jwt_token = await self.token_manager.create_access_token(request.identifier)
        refresh_token = await self.token_manager.create_refresh_token(key_obj.id)

        return schemas.TokenResponse(
            jwt=jwt_token,
            refresh_token=refresh_token
        )


    async def refresh(self, request: schemas.RefreshRequest) -> schemas.TokenResponse:
        """
        Use a refresh token to create a new access token.
        """
        refresh_token_obj = await self.token_manager.load_refresh_token(request.refresh_token)
        if not await refresh_token_obj.is_valid():
            raise ExpiredError("Token is expired.")

        jwt_token = await self.token_manager.create_access_token(request.identifier)
        return schemas.TokenResponse(jwt=jwt_token)


    async def validate(self, request: schemas.JWTValidateRequest) -> schemas.BoolResponse:
        """
        Validate a JWT token.
        Raises a %s exception if token is invalid.
        """
        token = await self.token_manager.load_access_token(request.jwt)
        if not await token.is_valid():
            raise ExpiredError("Token is expired.")
        return schemas.BoolResponse(result=True)


    async def register_key(self, request: schemas.RegisterKeyRequest) -> schemas.BoolResponse:
        """
        Register a new key so it can be used for authentication.
        """
        await self.key_manager.create_key(request.key, request.identifier)
        return schemas.BoolResponse(result=True)


    async def is_key_registerd(self, request: schemas.KeyRequest) -> schemas.BoolResponse:
        """
        Check if a given key is already registered.
        """
        key_hash = sha512(request.key.encode()).hexdigest()
        result = await self.key_manager.check_key_exists(key_hash)
        return schemas.BoolResponse(result=result)


    async def get_jwks(self) -> schemas.JWKSResponse:
        """
        Get the JWKS requried for authentication.
        See here for more details: https://auth0.com/docs/tokens/references/jwks-properties
        """
        rsa_obj = RSA.import_key(self.public_key)

        jwks_obj = schemas.JWKSResponse(
            alg=self.jwt_algorithm,
            kty=self.jwt_algorithm_family,
            use="sig",
            x5c=[self.public_key],
            n=INT_TO_BIG_ENDIAN(rsa_obj.n),
            e=INT_TO_BIG_ENDIAN(rsa_obj.e)
        )

        return jwks_obj
