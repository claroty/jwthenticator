import asyncio

loop = asyncio.new_event_loop()
db_lock = asyncio.Lock(loop=loop)