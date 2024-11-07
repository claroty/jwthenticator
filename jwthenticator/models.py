# pylint: disable=too-few-public-methods
from __future__ import absolute_import

from datetime import datetime

from sqlalchemy import create_engine, Integer, String, DateTime, ForeignKey
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker
from sqlalchemy_utils import database_exists, create_database
from sqlalchemy_utils.types.uuid import UUIDType

from jwthenticator.consts import DB_URI

engine = create_engine(DB_URI)
SessionMaker = sessionmaker(bind=engine)

class Base(sa.orm.DeclarativeBase):
    pass


class KeyInfo(Base):
    __tablename__ = "keys"
    id = sa.orm.mapped_column(Integer, primary_key=True, autoincrement=True)
    created = sa.orm.mapped_column(DateTime, default=datetime.utcnow())
    expires_at = sa.orm.mapped_column(DateTime)
    key_hash = sa.orm.mapped_column(String(256), unique=True)
    identifier = sa.orm.mapped_column(UUIDType(binary=False), nullable=False)


class RefreshTokenInfo(Base):
    __tablename__ = "refresh_tokens"
    id = sa.orm.mapped_column(Integer, primary_key=True, autoincrement=True)
    created = sa.orm.mapped_column(DateTime, default=datetime.utcnow())
    expires_at = sa.orm.mapped_column(DateTime)
    token = sa.orm.mapped_column(String(512))
    key_id = sa.orm.mapped_column(Integer, ForeignKey("keys.id"))


# Create database + tables
if not database_exists(DB_URI):
    create_database(DB_URI)
Base.metadata.create_all(engine)
