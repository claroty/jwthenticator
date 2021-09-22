from __future__ import absolute_import

from typing import Optional, List
from datetime import datetime, timedelta
from hashlib import sha512
from uuid import UUID, uuid4

import jwt
from asyncalchemy import create_session_factory

from jwthenticator.models import Base, RefreshTokenInfo
from jwthenticator.schemas import JWTPayloadData, RefreshTokenData
from jwthenticator.exceptions import InvalidTokenError, MissingJWTError
from jwthenticator.consts import JWT_ALGORITHM, REFRESH_TOKEN_EXPIRY, JWT_LEASE_TIME, JWT_AUDIENCE, DB_URI


class TokenManager:
    """
    Class responsible for the creation and loading of tokens
    """

    # pylint: disable=too-many-arguments,too-many-instance-attributes
    def __init__(self, public_key: str, private_key: Optional[str] = None, algorithm: str = JWT_ALGORITHM,
                 jwt_lease_time: int = JWT_LEASE_TIME, jwt_audience: List[str] = JWT_AUDIENCE, key_id: Optional[str] = None):
        """
        Accepts public + private key pairs.
        If only public key is given tokens can be loaded but not created.
        """
        # This is done to avoid an "exploit" where algorithm=none leaving the jwt tokens unsecure.
        if not algorithm or algorithm.lower() == "none":
            raise Exception("Algorithm can't be empty!")

        self.public_key = public_key
        self.private_key = private_key
        self.algorithm = algorithm
        self.jwt_lease_time = jwt_lease_time
        self.jwt_audience = jwt_audience if len(jwt_audience) > 0 else None
        self.jwt_headers = {"kid": key_id} if key_id else None

        self.refresh_token_schema = RefreshTokenData.Schema()
        self.jwt_payload_data_schema = JWTPayloadData.Schema()

        self.session_factory = create_session_factory(DB_URI, Base)


    async def create_access_token(self, identifier: UUID) -> str:
        """
        Creates new JWT token.
        :param identifier: A UUID identifier of who the token was created to.
        :return: The new JWT token string
        """
        if self.private_key is None:
            raise Exception("Private key required for JWT token creation")
        now = datetime.now()
        payload = JWTPayloadData(
            token_id=uuid4(),
            identifier=identifier,
            iat=int(now.timestamp()),
            exp=int((now + timedelta(seconds=self.jwt_lease_time)).timestamp()),
            aud=self.jwt_audience
        )
        encoded_payload = self.jwt_payload_data_schema.dump(payload)
        token_string = jwt.encode(encoded_payload, self.private_key, self.algorithm, headers=self.jwt_headers)
        return token_string


    async def load_access_token(self, token_string: str) -> JWTPayloadData:
        """
        Load + parse an existing JWT token.
        Raises exception if the token is incorrectly signed.
        """
        if not token_string:
            raise MissingJWTError
        token_dict: dict = jwt.decode(token_string, self.public_key, algorithms=[self.algorithm], options={"verify_exp": False})
        token_data = self.jwt_payload_data_schema.load(token_dict)
        return token_data


    async def create_refresh_token(self, key_id: int, expires_at: Optional[datetime] = None) -> str:
        """
        Create a new refresh token and insert to db.
        :param key_id: The id of the key the refresh token is created by.
        :return: The refresh token created.
        """
        if expires_at is None:
            expires_at = expires_at = datetime.now() + timedelta(seconds=REFRESH_TOKEN_EXPIRY)
        if expires_at <= datetime.now():
            raise Exception("Refresh token can't be created in the past")

        refresh_token_str = sha512(uuid4().bytes).hexdigest()
        async with self.session_factory() as session:
            refresh_token_info_obj = RefreshTokenInfo(
                expires_at=expires_at,
                token=refresh_token_str,
                key_id=key_id
            )
            await session.add(refresh_token_info_obj)
            await session.flush()
        return refresh_token_str


    async def check_refresh_token_exists(self, refresh_token: str) -> bool:
        """
        Check if a refresh token exists in DB.
        """
        async with self.session_factory() as session:
            if await session.query(RefreshTokenInfo).filter_by(token=refresh_token).count() == 1:
                return True
        return False


    async def load_refresh_token(self, refresh_token: str) -> RefreshTokenData:
        """
        Load a refresh token from DB.
        """
        if not await self.check_refresh_token_exists(refresh_token):
            raise InvalidTokenError("Invalid refresh token")
        async with self.session_factory() as session:
            refresh_token_info_obj = await session.query(RefreshTokenInfo).filter_by(token=refresh_token).first()
            refresh_token_data_obj = self.refresh_token_schema.load(self.refresh_token_schema.dump(refresh_token_info_obj))
            return refresh_token_data_obj
