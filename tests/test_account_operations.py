import logging
import os
import tempfile

from common_ci_utils.templating import Templating
from framework import config
from framework.connection import SSHConnection

log = logging.getLogger(__name__)


def test_account_operations(account_manager, unique_resource_name, random_hex):
    conn = SSHConnection().connection
    # account operations
    account_name = unique_resource_name(prefix="account")
    access_key = random_hex()
    secret_key = random_hex()
    config_root = config.ENV_DATA["config_root"]
    account_manager.create(account_name, access_key, secret_key, config_root)
    account_manager.list(config_root)
    account_manager.delete(config_root, account_name)
    account_manager.list()
