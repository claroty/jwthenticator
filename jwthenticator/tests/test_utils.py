import os
from importlib import reload
from os import environ
from typing import Tuple, Optional
import pytest

import jwthenticator.utils
from jwthenticator import consts
from jwthenticator.utils import get_rsa_key_pair
from jwthenticator.tests.utils import random_key, backup_environment

PUBLIC_KEY_PATH_ENV_KEY = "RSA_PUBLIC_KEY_PATH"
PRIVATE_KEY_PATH_ENV_KEY = "RSA_PRIVATE_KEY_PATH"
PUBLIC_KEY_VALUE_ENV_KEY = "RSA_PUBLIC_KEY"
PRIVATE_KEY_VALUE_ENV_KEY = "RSA_PRIVATE_KEY"


def _reload_env_vars_get_rsa_key_pair() -> Tuple[str, Optional[str]]:
    reload(consts)
    reload(jwthenticator.utils)
    return get_rsa_key_pair()


async def _create_random_file() -> Tuple[str, str]:
    random_data = await random_key(8)
    filename = f"test_tmp_file_{await random_key(5)}.txt"
    with open(filename, "w", encoding='utf8') as file:
        file.write(random_data)
    return filename, random_data


@backup_environment
@pytest.mark.asyncio
# Get key pair value from env (not the path)
async def test_get_rsa_key_pair_by_env_value() -> None:
    generated_public_key = await random_key(8)
    generated_private_key = await random_key(8)
    environ[PUBLIC_KEY_PATH_ENV_KEY] = ""
    environ[PRIVATE_KEY_PATH_ENV_KEY] = ""
    environ[PUBLIC_KEY_VALUE_ENV_KEY] = generated_public_key
    environ[PRIVATE_KEY_VALUE_ENV_KEY] = generated_private_key
    public_key, private_key = _reload_env_vars_get_rsa_key_pair()
    assert public_key == generated_public_key
    assert private_key == generated_private_key


@backup_environment
@pytest.mark.asyncio
# No keys or path inputted - create keys
async def test_get_rsa_key_pair_no_input() -> None:
    environ[PUBLIC_KEY_PATH_ENV_KEY] = ""
    environ[PRIVATE_KEY_PATH_ENV_KEY] = ""
    environ[PUBLIC_KEY_VALUE_ENV_KEY] = ""
    environ[PRIVATE_KEY_VALUE_ENV_KEY] = ""
    public_key, private_key = _reload_env_vars_get_rsa_key_pair()
    assert public_key.count("PUBLIC KEY-----") == 2

    # Type can be ignored because a private key should be generated
    assert private_key.count("PRIVATE KEY-----") == 2  # type: ignore

@backup_environment
@pytest.mark.asyncio
# File exists - read keys
async def test_get_rsa_key_pair_from_file() -> None:
    private_file_name, private_file_data = await _create_random_file()
    public_file_name, public_file_data = await _create_random_file()
    environ[PUBLIC_KEY_PATH_ENV_KEY] = public_file_name
    environ[PRIVATE_KEY_PATH_ENV_KEY] = private_file_name
    public_key, private_key = _reload_env_vars_get_rsa_key_pair()
    assert public_file_data in public_key

    # Type can be ignored because a private key should be generated
    assert private_file_data in private_key  # type: ignore
    os.remove(private_file_name)
    os.remove(public_file_name)


@backup_environment
@pytest.mark.asyncio
# Path exists and files do not exist - create them
async def test_get_rsa_key_pair_create_file() -> None:
    public_file_name = f"test_tmp_file_{await random_key(5)}.txt"
    private_file_name = f"test_tmp_file_{await random_key(5)}.txt"
    environ[PUBLIC_KEY_PATH_ENV_KEY] = public_file_name
    environ[PRIVATE_KEY_PATH_ENV_KEY] = private_file_name
    public_key, private_key = _reload_env_vars_get_rsa_key_pair()
    with open(public_file_name, 'r', encoding='utf8') as file:
        public_key_from_file = file.read()
    with open(private_file_name, 'r', encoding='utf8') as file:
        private_key_from_file = file.read()
    assert public_key_from_file == public_key
    assert private_key_from_file == private_key
    assert public_key_from_file.count("PUBLIC KEY-----") == 2
    assert private_key_from_file.count("PRIVATE KEY-----") == 2
    os.remove(public_file_name)
    os.remove(private_file_name)
