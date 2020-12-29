# pylint: disable=unused-argument
from __future__ import absolute_import

from aiohttp import web
from aiohttp.web import json_response

from jwthenticator.server_utils import authenticate

PORT = 8000
JWTHENTICATOR_HOST = "http://localhost:8080/"

app = web.Application()


async def insecure(request: web.Request) -> web.Response:
    return json_response({"success!": True})


@authenticate(JWTHENTICATOR_HOST)
async def secure(request: web.Request) -> web.Response:
    return json_response({"success!": True})


app.add_routes([
    web.get("/insecure", insecure),
    web.get("/secure", secure)
])


web.run_app(app, port=PORT)
