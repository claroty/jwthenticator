from __future__ import absolute_import

from os import environ

DAYS_TO_SECONDS = lambda x: x * 60 * 24


# Server consts
PORT = int(environ.get("PORT", 8080))
URL_PREFIX = URL_PREFIX = environ.get('URL_PREFIX', '')
DISABLE_EXTERNAL_API = bool(environ.get("DISABLE_EXTERNAL_API", ""))
DISABLE_INTERNAL_API = bool(environ.get("DISABLE_INTERNAL_API", ""))

# JWT consts
JWT_ALGORITHM = environ.get("JWT_ALGORITHM", "RS256")
JWT_ALGORITHM_FAMILY = environ.get("JWT_ALGORITHM_FAMILY", "RSA")
JWT_LEASE_TIME = int(environ.get("JWT_LEASE_TIME", 30 * 60)) # In seconds - 30 minutes
RSA_KEY_STRENGTH = int(environ.get("RSA_KEY_STRENGTH", 2048))
JWT_AUDIENCE = environ.get("JWT_AUDIENCE", None)

# Token consts
KEY_EXPIRY = int(environ.get("KEY_EXPIRY", DAYS_TO_SECONDS(120)))  # In seconds
REFRESH_TOKEN_EXPIRY = int(environ.get("REFRESH_TOKEN_EXPIRY", DAYS_TO_SECONDS(60)))   # In seconds

# Encryption keys
RSA_PUBLIC_KEY = environ.get("RSA_PUBLIC_KEY", None)
RSA_PRIVATE_KEY = environ.get("RSA_PRIVATE_KEY", None)
# Keys from file
RSA_PUBLIC_KEY_PATH = environ.get("RSA_PUBLIC_KEY_PATH", None)
RSA_PRIVATE_KEY_PATH = environ.get("RSA_PRIVATE_KEY_PATH", None)

# DB consts
DB_CONNECTOR = environ.get("DB_CONNECTOR", "postgresql+pg8000")
DB_USER = environ.get("DB_USER", "postgres")
DB_PASS = environ.get("DB_PASS", "")
DB_HOST = environ.get("DB_HOST", "localhost")
DB_NAME = environ.get("DB_NAME", "jwthenticator")

DB_URI = environ.get("DB_URI", f"{DB_CONNECTOR}://{DB_USER}:{DB_PASS}@{DB_HOST}/{DB_NAME}")
