from __future__ import absolute_import

from os.path import isfile
from typing import Tuple, Optional
from urllib.parse import urlparse

from jwt.utils import base64url_encode
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA1

from jwthenticator.consts import RSA_KEY_STRENGTH, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY, RSA_PUBLIC_KEY_PATH, RSA_PRIVATE_KEY_PATH


def get_rsa_key_pair() -> Tuple[str, Optional[str]]:
    """
    Get RSA key pair.
    Will get RSA key pair depending on available ENV variables, in the following order:
    1. Read file path from RSA_PUBLIC_PATH and PRIVATE_KEY_PATH and use the files there,
       If a path is specified (in RSA_PUBLIC_PATH and PRIVATE_KEY_PATH) but the files do
       not exist - they will be created and populated
    2. Use data directly in the env vars RSA_PUBLIC_KEY and RSA_PRIVATE_KEY
    3. Use stateless new keys
    :return (public_key, private_key): A key pair tuple.
        Will raise exception if key paths are given and fail to read.
    """
    if RSA_PUBLIC_KEY_PATH:
        if isfile(RSA_PUBLIC_KEY_PATH):
            return _read_rsa_keys_from_file()
        return _create_rsa_key_files()

    if RSA_PUBLIC_KEY:
        return RSA_PUBLIC_KEY, RSA_PRIVATE_KEY

    return create_rsa_key_pair()


def _read_rsa_keys_from_file() -> Tuple[str, Optional[str]]:
    with open(RSA_PUBLIC_KEY_PATH, 'r', encoding='utf8') as f_obj:
        public_key = f_obj.read()
    private_key = None
    if RSA_PRIVATE_KEY_PATH is not None:
        with open(RSA_PRIVATE_KEY_PATH, 'r', encoding='utf8') as f_obj:
            private_key = f_obj.read()
    return public_key, private_key


def _create_rsa_key_files() -> Tuple[str, Optional[str]]:
    public_key, private_key = create_rsa_key_pair()
    with open(RSA_PUBLIC_KEY_PATH, 'w', encoding='utf8') as f_obj:
        f_obj.write(public_key)
    with open(RSA_PRIVATE_KEY_PATH, 'w', encoding='utf8') as f_obj:
        f_obj.write(private_key)
    return public_key, private_key


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


def calculate_key_signature(public_key: str) -> str:
    """
    Calculate the SHA1 signature for a given RSA public key.
    Calculation follows the JWK RFC7517 section 4.8 meaning base64
        URL encoding of SHA1 signature of public RSA key.
    :param public_key: The public key to calculate signature for.
    """
    rsa_obj = RSA.import_key(public_key)
    rsa_der = rsa_obj.export_key("DER")

    hasher = SHA1.new()
    hasher.update(rsa_der)
    fingerprint = base64url_encode(hasher.digest())

    return fingerprint.decode("utf8")


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
