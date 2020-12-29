from __future__ import absolute_import

import random
from string import ascii_letters
from datetime import datetime, timedelta
from hashlib import sha512
from uuid import uuid4


async def random_key(length: int = 32) -> str:
    return "".join([random.choice(ascii_letters) for i in range(length)])


def sync_random_key(length: int = 32) -> str:
    """
    Sync version is so function can be used as a function param default value.
    """
    return "".join([random.choice(ascii_letters) for i in range(length)])


async def random_refresh_token() -> str:
    return sha512(uuid4().bytes).hexdigest()


async def hash_key(key: str) -> str:
    return sha512(key.encode()).hexdigest()


async def future_datetime(seconds: int = 0) -> datetime:
    return datetime.utcnow() + timedelta(seconds=seconds)
