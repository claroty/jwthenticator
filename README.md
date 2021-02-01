# JWThenticator
A cloud first service for key to JWT authentication library and server written in Python 3.


## Intro
JWThenticator was written for client authentication in micro-services architectures with usage of API gateways in mind.\
Although there are multiple open-source projects for authenticating users in exchange for JWT (json web token), we couldn't find any project that fit our need for a key based authentication for our clients. This is beneficial for any client authentication and more specifically for IoT.\
The service is stateless, Docker first service for cloud authentication, but can generally be used for any key to JWT authentication and in multiple different architectures (see example [below](#example-architecture)).


## How To Use
### Pip
```bash
pip install jwthenticator
```
To run as a server you can run: `python3 -m jwthenticator.server`.\
Make sure to configure the proper database to be used via the environment variables exposed in [jwthenticator/consts.py](jwthenticator/consts.py) file.\
By default PostgreSQL is used and a basic local config setup is:
```bash
export DB_USER="my-postgres-user"
export DB_PASS="my-postgres-pass"
```
Note - if RSA keys are not provided (via the environment variables `RSA_PUBLIC_KEY` + `RSA_PRIVATE_KEY` or `RSA_PUBLIC_KEY_PATH` + `RSA_PRIVATE_KEY_PATH`), a new RSA pair will be generated every time the systems goes up.

### Docker
```bash
docker pull clarotyltd/jwthenticator
docker run -p 8080:8080 clarotyltd/jwthenticator
```
A database is needed to be linked or configured to the image.\
See [examples/docker-compose.yml](examples/docker-compose.yml) for a full example, run it using:
```bash
cd examples
docker-compose up
```

### From Source
The project uses [poetry](https://github.com/python-poetry/poetry) for dependency management and packaging.\
To run from source clone project and:
```bash
pip install poetry
poetry install
```


## Documentation
- API documentation - [openapi.yaml](openapi.yaml) file (ex Swagger)
- Configurable environment variables - [jwthenticator/consts.py](jwthenticator/consts.py)
- Code usage examples - [Code Examples](#code-examples)
- Example architecture - [Example Architecture](#example-architecture)
- Diagrams - [docs](docs) folder for some UML [sequence diagrams](https://sequencediagram.org/) and Python diagrams using [diagrams](https://github.com/mingrammer/diagrams)


## Code Examples
For full examples see the [examples](jwthenticator/examples) folder.

### Client
To make it easier to work agains a JWThenticator protected server (either directly or via API gateway), a client class is provided.\
The `Client` class handles auth state management against JWThenticator. It handles JWthenticator responses for you, performs authentication for you, and JWT refresh when needed.\
It exposes a `request_with_auth` function (and the simpler `get_with_auth` and `post_with_auth`) that manages all interactions against the secured service and the JWThenticator itself for you.\
Example usage:
```python
from uuid import uuid4
from jwthenticator.client import Client

identifier = uuid4()
client = Client("https://my-jwthenticator-host/", identifier, key="my-awesome-key")
response = await client.get_with_auth("https://my-secure-server/")
```

### Server
Although JWThenticator was designed with an API gateway in mind, it can be used to authenticate server endpoints directly.\
For easy usage with an [aiohttp](https://docs.aiohttp.org/en/stable/) Python server you can do the following:
```python
from aiohttp import web
from jwthenticator.server_utils import authenticate

app = web.Application()

@authenticate("https://my-jwthenticator-host/")
async def secure_index(request: web.Request) -> web.Response:
    return "Secure hello world!"

app.add_routes([web.get("/", secure_index)])
web.run_app(app)
```


## Example Architecture
A visual example on how JWThenticator is and can be used.\
Additional ones can be found in [docs](docs) folder.

### API Gateway Architecture
Generated from [docs/api_gateway_architecture_diagram.py](docs/api_gateway_architecture_diagram.py)\
![API Gateway Architecture](https://user-images.githubusercontent.com/3015856/103092541-3cdd1c00-4600-11eb-807d-6033f6fdfa72.png)

### API Gateway REST Sequence Diagram
Generated from [docs/api_gateway_flow.diag](docs/api_gateway_flow.diag)\
![API Gateway REST Sequence Diagram](https://user-images.githubusercontent.com/3015856/103092521-2931b580-4600-11eb-8a0e-a4fb7ccf41c0.png)

## How it works
There are 3 key components to JWThenticator:

### Keys
Keys that are registered against the service and can then be used for authentication.\
All keys are registered to the database, have an expiration time (change default of 30 minutes using the env var `KEY_EXPIRY` in seconds), identifier of the registrant and some other metadata stored about them.\
The identifier is usefull if a key needs to be linked later to a specific server or route.

### Refresh tokens
Since JWTs are short lived and keys should be kept safe, an intermediate method is needed so we don't have a long lived JWTs or use our secret key every 30 minutes (by default). This is where refresh token come into play.\
Refresh tokens are received from a successfull authentication and are used for receiving a new JWTs after they expire.\
They are recoreded in the database, have an expiration time (change default of 60 days using  the env var `REFRESH_TOKEN_EXPIRY` in seconds) and some other metadata stored about them.\
You can check out [jwthenticator/models.py](jwthenticator/models.py) to see what data is stored in the database.

### JWTs
The industry standard JWT ([RFC 7519](https://tools.ietf.org/html/rfc7519)). The JWT is used for verification against an API gateway, JWThenticator itself, or any service / code you use for you auth verification.\
The JWTs are short lived (as they should be) with a configurable lease time via `JWT_LEASE_TIME` env var.\
Additionaly, similarly to the keys we use a UUID identifier in the authentication process and store it in the JWT's payload. This is useful for better client identification or smarter k8s routing.


## Addtional Features
- All consts can be overriden via environment variables, see [jwthenticator/consts.py](jwthenticator/consts.py) for the full list.
- Service contains both internal and public routes, the admin / public API's can be disabled by setting the `DISABLE_EXTERNAL_API` or `DISABLE_INTERNAL_API` env vars. This is very important when running the service in production environments, you don't want to expose the key registration to the general public :).
- The service can be used with any JWT verification service or API gateway using the industry standard JWKS ([RFC 7517](https://tools.ietf.org/html/rfc7517)) via `/jwks` API call.
- JWThenticator can be used as an [Nginx authentication](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html) backend using the `/validate_request` API call.
- Some requests require giving a UUID identifier. Even though the service doesn't enforce its verification, it can be used as a mean of identifiying incoming users, smart routing, and later for additional validations.
- All REST API schemas are defined using Python `dataclass`es and validated using [marshmallow_dataclass](https://github.com/lovasoa/marshmallow_dataclass), see [schemas.py](jwthenticator/schemas.py).
