from __future__ import absolute_import

from environs import Env

DAYS_TO_SECONDS = lambda x: x * 60 * 24

env = Env()


# Server consts
PORT = env.int("PORT", 8080)
URL_PREFIX = URL_PREFIX = env.str("URL_PREFIX", "")
DISABLE_EXTERNAL_API = env.bool("DISABLE_EXTERNAL_API", False)
DISABLE_INTERNAL_API = env.bool("DISABLE_INTERNAL_API", False)

# JWT consts
JWT_ALGORITHM = env.str("JWT_ALGORITHM", "RS256")
JWT_ALGORITHM_FAMILY = env.str("JWT_ALGORITHM_FAMILY", "RSA")
JWT_LEASE_TIME = env.int("JWT_LEASE_TIME", 30 * 60) # In seconds - 30 minutes
JWT_AUDIENCE = env.list("JWT_AUDIENCE", [])

# Token consts
KEY_EXPIRY = env.int("KEY_EXPIRY", DAYS_TO_SECONDS(120))  # In seconds
REFRESH_TOKEN_EXPIRY = env.int("REFRESH_TOKEN_EXPIRY", DAYS_TO_SECONDS(60))   # In seconds

# Keys from env
RSA_PUBLIC_KEY = env("RSA_PUBLIC_KEY", None)
RSA_PRIVATE_KEY = env("RSA_PRIVATE_KEY", None)
# Keys from file
RSA_PUBLIC_KEY_PATH = env("RSA_PUBLIC_KEY_PATH", None)
RSA_PRIVATE_KEY_PATH = env("RSA_PRIVATE_KEY_PATH", None)
# If no key is given, used for key generation
RSA_KEY_STRENGTH = env.int("RSA_KEY_SIZE", 2048)

# DB consts
DB_CONNECTOR = env.str("DB_CONNECTOR", "postgresql+pg8000")
DB_USER = env.str("DB_USER", "postgres")
DB_PASS = env.str("DB_PASS", "")
DB_HOST = env.str("DB_HOST", "localhost")
DB_NAME = env.str("DB_NAME", "jwthenticator")

DB_URI = env.str("DB_URI", f"{DB_CONNECTOR}://{DB_USER}:{DB_PASS}@{DB_HOST}/{DB_NAME}")
