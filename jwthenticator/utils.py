from __future__ import absolute_import

from typing import Tuple, Optional
from urllib.parse import urlparse

from Cryptodome.PublicKey import RSA

from jwthenticator.consts import RSA_KEY_STRENGTH, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY, RSA_PUBLIC_KEY_PATH, RSA_PRIVATE_KEY_PATH


def get_rsa_key_pair() -> Tuple[str, Optional[str]]:
    """
    Get RSA key pair.
    Will try to get them by this order:
    1. RSA_PUBLIC/PRIVATE_KEY_PATH
    2. RSA_PUBLIC/PRIVATE_KEY
    3. Generate new keys.
    :return (public_key, private_key): A key pair tuple.
        Will raise exception if key paths are given and fail to read.
    """
    if RSA_PUBLIC_KEY_PATH is not None:
        # Read public key.
        with open(RSA_PUBLIC_KEY_PATH) as f_obj:
            public_key = f_obj.read()

        # Read private key if given.
        private_key = None
        if RSA_PRIVATE_KEY_PATH is not None:
            with open(RSA_PRIVATE_KEY_PATH) as f_obj:
                private_key = f_obj.read()

        return (public_key, private_key)

    if RSA_PUBLIC_KEY is not None:
        return (RSA_PUBLIC_KEY, RSA_PRIVATE_KEY)

    return create_rsa_key_pair()


def create_rsa_key_pair() -> Tuple[str, str]:
    """
    Create RSA key pair.
    Function is sync so it can be used from __init__ func.
    :return (public_key, private_key): A key pair tuple.
    """
    key = RSA.generate(RSA_KEY_STRENGTH)
    public_key = key.publickey().export_key().decode()
    private_key = key.export_key().decode()
    return public_key, private_key


def verify_url(url: str) -> bool:
    """
    Verifies a given URL is valid and will be accepted by http client.
    """
    parsed_url = urlparse(url)
    return all([parsed_url.scheme, parsed_url.netloc])


def fix_url_path(url: str) -> str:
    """
    Add "/" to end of URL, if URL has path and doesn't end with "/"
    the path will be removed by urljoin.
    """
    return url if url.endswith("/") else url + "/"
