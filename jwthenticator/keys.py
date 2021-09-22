from __future__ import absolute_import

from typing import Optional
from datetime import datetime, timedelta
from hashlib import sha512
from uuid import UUID

from asyncalchemy import create_session_factory

from jwthenticator.schemas import KeyData
from jwthenticator.models import Base, KeyInfo
from jwthenticator.exceptions import InvalidKeyError
from jwthenticator.consts import KEY_EXPIRY, DB_URI


class KeyManager:
    """
    Class used for creation and loading of keys.
    """

    def __init__(self) -> None:
        self.session_factory = create_session_factory(DB_URI, Base)
        self.key_schema = KeyData.Schema()


    async def create_key(self, key: str, identifier: UUID, expires_at: Optional[datetime] = None) -> bool:
        """
        Add a new key to database.
        Will update the key's expiry date if key already exists.
        :param key: The key to register.
        :return: Returns True if successfull, raises exception otherwise.
        """
        if expires_at is None:
            expires_at = datetime.now() + timedelta(seconds=KEY_EXPIRY)
        key_hash = sha512(key.encode()).hexdigest()

        # If key already exists, update expiry date.
        if await self.check_key_exists(key_hash):
            return await self.update_key_expiry(key_hash, expires_at)

        key_obj = KeyInfo(
            expires_at=expires_at,
            key_hash=key_hash,
            identifier=identifier
        )
        async with self.session_factory() as session:
            await session.add(key_obj)
        return True


    async def check_key_exists(self, key_hash: str) -> bool:
        """
        Check if a key exists in DB.
        """
        async with self.session_factory() as session:
            if await session.query(KeyInfo).filter_by(key_hash=key_hash).count() == 1:
                return True
        return False


    async def update_key_expiry(self, key_hash: str, expires_at: datetime) -> bool:
        """
        Update the expiry date of an existing key.
        """
        if not await self.check_key_exists(key_hash):
            raise InvalidKeyError("Invalid key")
        async with self.session_factory() as session:
            key_info_obj = await session.query(KeyInfo).filter_by(key_hash=key_hash).first()
            key_info_obj.expires_at = expires_at
        return True


    async def get_key(self, key_hash: str) -> KeyData:
        """
        Load key data from database.
        """
        if not await self.check_key_exists(key_hash):
            raise InvalidKeyError("Invalid key")
        async with self.session_factory() as session:
            key_info_obj = await session.query(KeyInfo).filter_by(key_hash=key_hash).first()
            key_data_obj = self.key_schema.load((self.key_schema.dump(key_info_obj)))
            return key_data_obj
