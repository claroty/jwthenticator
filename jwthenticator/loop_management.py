import asyncio
from jwthenticator.consts import DB_URI

main_event_loop = asyncio.new_event_loop()
db_lock = asyncio.Lock()

def is_using_sqlite()->bool:
    return "sqlite://" in DB_URI
