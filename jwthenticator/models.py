# pylint: disable=too-few-public-methods
from __future__ import absolute_import

from datetime import datetime, timezone
from sqlalchemy import create_engine, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import sessionmaker, DeclarativeBase, mapped_column
from sqlalchemy_utils import database_exists, create_database
from sqlalchemy_utils.types.uuid import UUIDType
from jwthenticator.consts import DB_URI
from jwthenticator.utils import utcnow

engine = create_engine(DB_URI)
SessionMaker = sessionmaker(bind=engine)


class DateTimeMixin:
    _created = mapped_column("created", DateTime, default=utcnow().replace(tzinfo=None))
    _expires_at = mapped_column("expires_at", DateTime)

    @property
    def created(self)-> datetime:
        if self._created and self._created.tzinfo is None:
            return self._created.replace(tzinfo=timezone.utc)
        return self._created

    @created.setter
    def created(self, created: datetime)-> None:
        if created and created.tzinfo:
            self._created = created.astimezone(timezone.utc).replace(tzinfo=None)
        else:
            self._created = created

    @property
    def expires_at(self)-> datetime:
        if self._expires_at and self._expires_at.tzinfo is None:
            return self._expires_at.replace(tzinfo=timezone.utc)
        return self._expires_at

    @expires_at.setter
    def expires_at(self, expires_at: datetime)-> None:
        if expires_at and expires_at.tzinfo:
            self._expires_at = expires_at.astimezone(timezone.utc).replace(tzinfo=None)
        else:
            self._expires_at = expires_at

class Base(DeclarativeBase, DateTimeMixin):
    pass

class KeyInfo(Base):
    __tablename__ = "keys"
    id = mapped_column(Integer, primary_key=True, autoincrement=True)
    key_hash = mapped_column(String(256), unique=True)
    identifier = mapped_column(UUIDType(binary=False), nullable=False)


class RefreshTokenInfo(Base):
    __tablename__ = "refresh_tokens"
    id = mapped_column(Integer, primary_key=True, autoincrement=True)
    token = mapped_column(String(512))
    key_id = mapped_column(Integer, ForeignKey("keys.id"))


# Create database + tables
if not database_exists(DB_URI):
    create_database(DB_URI)
Base.metadata.create_all(engine)
