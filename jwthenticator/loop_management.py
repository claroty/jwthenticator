import asyncio
from jwthenticator.consts import DB_URI

loop = asyncio.new_event_loop()
db_lock = asyncio.Lock(loop=loop)

def is_using_sqlite()->bool:
    return "sqlite" in DB_URI