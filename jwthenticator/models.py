# pylint: disable=too-few-public-methods
from __future__ import absolute_import

from typing import Any

from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy_utils import database_exists, create_database
from sqlalchemy_utils.types.uuid import UUIDType
from sqlalchemy.ext.hybrid import hybrid_property
from datetime import datetime, timezone
from jwthenticator.consts import DB_URI
from jwthenticator.utils import utcnow

engine = create_engine(DB_URI)
SessionMaker = sessionmaker(bind=engine)

Base = declarative_base()   # type: Any # pylint: disable=invalid-name


class KeyInfo(Base):
    __tablename__ = "keys"
    id = Column(Integer, primary_key=True, autoincrement=True)
    _created = Column("created", DateTime, default=utcnow())
    expires_at = Column(DateTime)
    key_hash = Column(String(256), unique=True)
    identifier = Column(UUIDType(binary=False), nullable=False) # type: ignore

    @hybrid_property
    def created(self):
        if self._created and self._created.tzinfo is None:
            return self._created.replace(tzinfo=timezone.utc)
        return self._created

    @created.setter
    def created(self, created: datetime):
        if created and created.tzinfo:
            self._created = created.astimezone(timezone.utc).replace(tzinfo=None)
        else:
            self._created = created
    

class RefreshTokenInfo(Base):
    __tablename__ = "refresh_tokens"
    id = Column(Integer, primary_key=True, autoincrement=True)
    _created = Column("created", DateTime, default=utcnow())
    _expires_at = Column("expires_at", DateTime)
    token = Column(String(512))
    key_id = Column(Integer, ForeignKey("keys.id"))

    @hybrid_property
    def created(self):
        if self._created and self._created.tzinfo is None:
            return self._created.replace(tzinfo=timezone.utc)
        return self._created

    @created.setter
    def created(self, created: datetime):
        if created and created.tzinfo:
            self._created = created.astimezone(timezone.utc).replace(tzinfo=None)
        else:
            self._created = created

    @hybrid_property
    def expires_at(self):
        if self._expires_at and self._expires_at.tzinfo is None:
            return self._expires_at.replace(tzinfo=timezone.utc)
        return self._expires_at

    @expires_at.setter
    def expires_at(self, expires_at: datetime):
        if expires_at and expires_at.tzinfo:
            self._expires_at = expires_at.astimezone(timezone.utc).replace(tzinfo=None)
        else:
            self._expires_at = expires_at

# Create database + tables
if not database_exists(DB_URI):
    create_database(DB_URI)
Base.metadata.create_all(engine)
