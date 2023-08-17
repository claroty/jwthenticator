from __future__ import absolute_import

from typing import Optional
from datetime import datetime, timedelta
from hashlib import sha512
from uuid import UUID

from sqlalchemy import select, func

from jwthenticator.utils import create_async_session_factory
from jwthenticator.schemas import KeyData
from jwthenticator.models import Base, KeyInfo
from jwthenticator.exceptions import InvalidKeyError
from jwthenticator.consts import KEY_EXPIRY, ASYNC_DB_URI


class KeyManager:
    """
    Class used for creation and loading of keys.
    """

    def __init__(self) -> None:
        self.async_session_factory = create_async_session_factory(ASYNC_DB_URI, Base)
        self.key_schema = KeyData.Schema()


    async def create_key(self, key: str, identifier: UUID, expires_at: Optional[datetime] = None) -> bool:
        """
        Add a new key to database.
        Will update the key's expiry date if key already exists.
        :param key: The key to register.
        :return: Returns True if successfull, raises exception otherwise.
        """
        if expires_at is None:
            expires_at = datetime.utcnow() + timedelta(seconds=KEY_EXPIRY)
        key_hash = sha512(key.encode()).hexdigest()

        # If key already exists, update expiry date.
        if await self.check_key_exists(key_hash):
            return await self.update_key_expiry(key_hash, expires_at)

        key_obj = KeyInfo(
            expires_at=expires_at,
            key_hash=key_hash,
            identifier=identifier
        )
        async with self.async_session_factory() as session:
            async with session.begin():
                session.add(key_obj)
        return True


    async def check_key_exists(self, key_hash: str) -> bool:
        """
        Check if a key exists in DB.
        """
        async with self.async_session_factory() as session:
            query = select(func.count(KeyInfo.id)).where(KeyInfo.key_hash == key_hash)
            return (await session.scalar(query)) == 1


    async def update_key_expiry(self, key_hash: str, expires_at: datetime) -> bool:
        """
        Update the expiry date of an existing key.
        """
        if not await self.check_key_exists(key_hash):
            raise InvalidKeyError("Invalid key")
        async with self.async_session_factory() as session:
            query = select(KeyInfo).where(KeyInfo.key_hash == key_hash)
            key_info_obj = await session.scalar(query)
            key_info_obj.expires_at = expires_at
        return True


    async def get_key(self, key_hash: str) -> KeyData:
        """
        Load key data from database.
        """
        if not await self.check_key_exists(key_hash):
            raise InvalidKeyError("Invalid key")
        async with self.async_session_factory() as session:
            query = select(KeyInfo).where(KeyInfo.key_hash == key_hash)
            key_info_obj = await session.scalar(query)
            key_data_obj = self.key_schema.load((self.key_schema.dump(key_info_obj)))
            return key_data_obj
