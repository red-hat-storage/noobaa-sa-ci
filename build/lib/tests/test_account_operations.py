import logging

from common_ci_utils.random_utils import (
    generate_random_hex,
    generate_unique_resource_name,
)

from framework import config

log = logging.getLogger(__name__)


def test_account_operations(account_manager):
    # account operations
    account_name = generate_unique_resource_name(prefix="account")
    access_key = generate_random_hex()
    secret_key = generate_random_hex()
    config_root = config.ENV_DATA["config_root"]
    account_manager.create(account_name, access_key, secret_key, config_root)
    account_manager.list(config_root)
    account_manager.delete(account_name, config_root)
    account_manager.list()
