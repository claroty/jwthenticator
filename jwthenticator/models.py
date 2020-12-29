# pylint: disable=too-few-public-methods
from __future__ import absolute_import

from typing import Any
from datetime import datetime

from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy_utils import database_exists, create_database
from sqlalchemy_utils.types.uuid import UUIDType

from jwthenticator.consts import DB_URI

engine = create_engine(DB_URI)
SessionMaker = sessionmaker(bind=engine)

Base = declarative_base()   # type: Any # pylint: disable=invalid-name


class KeyInfo(Base):
    __tablename__ = "keys"
    id = Column(Integer, primary_key=True, autoincrement=True)
    created = Column(DateTime, default=datetime.now)
    expires_at = Column(DateTime)
    key_hash = Column(String(256), unique=True)
    identifier = Column(UUIDType(binary=False), nullable=False)


class RefreshTokenInfo(Base):
    __tablename__ = "refresh_tokens"
    id = Column(Integer, primary_key=True, autoincrement=True)
    created = Column(DateTime, default=datetime.now)
    expires_at = Column(DateTime)
    token = Column(String(512))
    key_id = Column(Integer, ForeignKey("keys.id"))


# Create database + tables
if not database_exists(DB_URI):
    create_database(DB_URI)
Base.metadata.create_all(engine)
