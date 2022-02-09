from datetime import datetime
import os
from importlib import reload
from os import environ
from typing import Tuple, Optional, AsyncGenerator
import pytest

import aiofiles
from async_generator import asynccontextmanager
from Cryptodome.PublicKey import RSA

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


@asynccontextmanager
async def _create_random_file() -> AsyncGenerator[Tuple[str, str], None]:
    random_data = await random_key(8)
    filename = f"test_tmp_file_{datetime.now()}.txt"
    # ignore type due to mypy-aiofiles issues
    async with aiofiles.open(filename, "w", encoding="utf8") as file:  # type: ignore
        await file.write(random_data)
    try:
        yield filename, random_data
    finally:
        os.remove(filename)


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
    assert RSA.import_key(str(private_key))
    assert RSA.import_key(str(public_key))


@backup_environment
@pytest.mark.asyncio
# File exists - read keys
async def test_get_rsa_key_pair_from_file() -> None:
    # Pylint sets a false positive
    async with _create_random_file() as (
        private_file_name,
        private_file_data,
    ), _create_random_file() as (
        public_file_name,
        public_file_data,
    ):  # pylint: disable=not-async-context-manager
        environ[PUBLIC_KEY_PATH_ENV_KEY] = public_file_name
        environ[PRIVATE_KEY_PATH_ENV_KEY] = private_file_name
        public_key, private_key = _reload_env_vars_get_rsa_key_pair()
        assert public_file_data in public_key

        # Type can be ignored because a private key should be generated
        assert private_file_data in private_key  # type: ignore


@backup_environment
@pytest.mark.asyncio
# Path exists and files do not exist - create them
async def test_get_rsa_key_pair_create_file() -> None:
    public_file_name = f"test_tmp_file_{datetime.now()}.txt"
    private_file_name = f"test_tmp_file_{datetime.now()}.txt"
    environ[PUBLIC_KEY_PATH_ENV_KEY] = public_file_name
    environ[PRIVATE_KEY_PATH_ENV_KEY] = private_file_name
    try:
        public_key, private_key = _reload_env_vars_get_rsa_key_pair()
        # ignore type due to mypy-aiofiles issues
        async with aiofiles.open(public_file_name, "r", encoding="utf8") as file:  # type: ignore
            public_key_from_file = await file.read()
        async with aiofiles.open(private_file_name, "r", encoding="utf8") as file:  # type: ignore
            private_key_from_file = await file.read()
        assert public_key_from_file == public_key
        assert private_key_from_file == private_key
        assert RSA.import_key(public_key_from_file)
        assert RSA.import_key(private_key_from_file)
    finally:
        try:
            os.remove(public_file_name)
        finally:
            os.remove(private_file_name)
