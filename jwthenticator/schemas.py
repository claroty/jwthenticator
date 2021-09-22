# pylint: disable=invalid-name
from __future__ import absolute_import

import uuid
from dataclasses import field
from typing import Optional, List, ClassVar, Type, Dict, Any
from datetime import datetime
from collections.abc import Hashable

from marshmallow import Schema, fields, post_dump
from marshmallow_dataclass import dataclass, NewType, add_schema

from jwthenticator.consts import JWT_ALGORITHM, JWT_ALGORITHM_FAMILY

# Define the UUID type that uses Marshmallow's UUID + Python's UUID
UUID = NewType("UUID", uuid.UUID, field=fields.UUID)


# Marshmallow base schema for skipping None values on dump
class BaseSchema(Schema):
    SKIP_VALUES = {None}

    @post_dump
    # pylint: disable=unused-argument
    def remove_skip_values(self, data: Any, many: bool) -> Dict[Any, Any]:
        return {
            key: value for key, value in data.items()
            if not isinstance(value, Hashable) or value not in self.SKIP_VALUES
        }


# Data dataclasses (that match the sqlalchemy models)
@dataclass  # pylint: disable=used-before-assignment
class KeyData:
    Schema: ClassVar[Type[Schema]] = Schema
    id: int
    created: datetime
    expires_at: datetime
    key_hash: str
    key: Optional[str] = field(default=None, repr=False, metadata=dict(load_only=True))

    async def is_valid(self) -> bool:
        return self.expires_at > datetime.now()


@dataclass
class RefreshTokenData:
    Schema: ClassVar[Type[Schema]] = Schema
    id: int
    created: datetime
    expires_at: datetime
    token: str
    key_id: int

    async def is_valid(self) -> bool:
        return self.expires_at > datetime.now()


# Skipping None values on dump since 'aud' is optional and can't be None/empty
@add_schema(base_schema=BaseSchema)
@dataclass
class JWTPayloadData:
    Schema: ClassVar[Type[Schema]] = Schema
    token_id: UUID   # JWT token identifier
    identifier: UUID # Identifier of who the JWT was issued to
    iat: int    # Issued at timestamp
    exp: int    # Expires at timestamp
    aud: Optional[List[str]] = None   # JWT Audience

    async def is_valid(self) -> bool:
        return self.exp > datetime.now().timestamp()


# Request dataclasses
@dataclass
class KeyRequest:
    Schema: ClassVar[Type[Schema]] = Schema
    key: str


@dataclass
class RegisterKeyRequest(KeyRequest):
    identifier: UUID # Identifier of who the JWT was issued to


@dataclass
class RefreshRequest:
    Schema: ClassVar[Type[Schema]] = Schema
    refresh_token: str
    identifier: UUID


@dataclass
class JWTValidateRequest:
    Schema: ClassVar[Type[Schema]] = Schema
    jwt: str


@dataclass
class AuthRequest:
    Schema: ClassVar[Type[Schema]] = Schema
    key: str = field(repr=False)
    identifier: UUID


# Response dataclasses
@dataclass
class TokenResponse:
    Schema: ClassVar[Type[Schema]] = Schema
    jwt: str
    refresh_token: Optional[str] = None


@dataclass
class BoolResponse:
    Schema: ClassVar[Type[Schema]] = Schema
    result: Optional[bool]
    message: Optional[str] = None


@dataclass
class JWKPayload:   # pylint: disable=too-many-instance-attributes
    """
    See https://auth0.com/docs/tokens/json-web-tokens/json-web-key-set-properties
    """
    Schema: ClassVar[Type[Schema]] = Schema
    x5c: List[str]  # x.509 certificate chain
    n: bytes    # RSA public key modulus
    e: bytes    # RSA public key exponent
    x5t: str    # x.509 SHA-1 thumbprint
    kid: str    # Unique key identifier
    alg: str = JWT_ALGORITHM    # Key algorithm
    kty: str = JWT_ALGORITHM_FAMILY # Key algorithm family
    use: str = "sig"    # How key will be used, sig (signature) by default


@dataclass
class JWKSResponse:
    Schema: ClassVar[Type[Schema]] = Schema
    keys: List[JWKPayload]
