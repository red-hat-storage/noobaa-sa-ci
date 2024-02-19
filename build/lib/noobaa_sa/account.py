"""
Module which contain account operations like create, delete, list and update
"""

import logging
import os
import tempfile
from datetime import datetime
from abc import ABC, abstractmethod

from common_ci_utils.templating import Templating

from framework import config
from framework.ssh_connection_manager import SSHConnectionManager
from noobaa_sa.defaults import MANAGE_NSFS
from noobaa_sa import constants
from noobaa_sa.exceptions import (
    AccountCreationFailed,
    AccountDeletionFailed,
    AccountListFailed,
)
from utility.utils import get_noobaa_sa_host_home_path

log = logging.getLogger(__name__)


class Account(ABC):
    """
    A base class for Account related operations.
    Should be inherited by specific deployment type like DB and NSFS
    """

    def __init__(self, account_json):
        """
        Initialize necessary variable

        Args:
            account_json (str): Path to account json file

        """
        self.account_json = account_json
        self.manage_nsfs = MANAGE_NSFS
        self.config_root = config.ENV_DATA["config_root"]
        self.conn = SSHConnectionManager().connection

    @abstractmethod
    def create(self):
        pass

    @abstractmethod
    def update(self, account_name):
        pass

    @abstractmethod
    def delete(self, account_name):
        pass


class NSFSAccount(Account):
    """
    Account operations for NSFS Deployment type
    """

    def create(
        self,
        account_name,
        access_key,
        secret_key,
        config_root=None,
        fs_backend=constants.DEFAULT_FS_BACKEND,
    ):
        """
        Account creation using file

        Args:
            config_root (str): Path to config root
        """
        account_email = config.ENV_DATA["email"]

        hd = get_noobaa_sa_host_home_path()
        bucket_path = os.path.join(hd, f"fs_{account_name}")

        # create bucket path
        cmd = f"sudo mkdir {bucket_path}"
        self.conn.exec_cmd(cmd)

        # form the account json file
        templating = Templating(base_path=config.ENV_DATA["template_dir"])
        account_template = "account.json"
        account_data = {
            "account_name": account_name,
            "account_email": account_email,
            # creation_date is required due to https://bugzilla.redhat.com/show_bug.cgi?id=2260325
            "creation_date": datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "access_key": access_key,
            "secret_key": secret_key,
            "bucket_path": bucket_path,
            "fs_backend": fs_backend,
        }
        account_data_full = templating.render_template(account_template, account_data)
        log.info(f"account content: {account_data_full}")

        # write to file
        with tempfile.NamedTemporaryFile(
            mode="w+", prefix="account_", delete=False
        ) as account_file:
            account_file.write(account_data_full)

        # upload to noobaa-sa host
        self.conn.exec_cmd(f"sudo mkdir -p {os.path.dirname(account_file.name)}")
        self.conn.exec_cmd(f"sudo chmod a+w {os.path.dirname(account_file.name)}")
        self.conn.upload_file(account_file.name, account_file.name)

        if config_root is None:
            config_root = self.config_root
        log.info(f"config root path: {config_root}")
        log.info("Adding account for NSFS deployment")
        cmd = f"sudo /usr/local/noobaa-core/bin/node {self.manage_nsfs} account add --config_root {config_root} --from_file {account_file.name}"
        retcode, stdout, stderr = self.conn.exec_cmd(cmd)
        if retcode != 0:
            raise AccountCreationFailed(
                f"Creation of account failed with error {stdout}"
            )
        log.info("Account created successfully")

    def list(self, config_root=None):
        """
        Lists accounts

        Args:
            config_root (str): Path to config root

        """
        if config_root is None:
            config_root = self.config_root
        log.info("Listing accounts for NSFS deployment")
        cmd = f"sudo /usr/local/noobaa-core/bin/node {self.manage_nsfs} account list --config_root {config_root}"
        retcode, stdout, stderr = self.conn.exec_cmd(cmd)
        log.info(stdout)
        if retcode != 0:
            raise AccountListFailed(f"Listing of accounts failed with error {stderr}")

    def delete(self, account_name=None, config_root=None):
        """
        Account Deletion

        Args:
            config_root (str): Path to config root
            account_json (str): Path to account json file

        """
        if config_root is None:
            config_root = self.config_root
        log.info("Deleting account for NSFS deployment")
        log.info(account_name)
        log.info(config_root)
        cmd = f"sudo /usr/local/noobaa-core/bin/node {self.manage_nsfs} account delete --name {account_name} --config_root {config_root}"
        retcode, stdout, stderr = self.conn.exec_cmd(cmd)
        if retcode != 0:
            raise AccountDeletionFailed(f"Deleting account failed with error {stderr}")

    def update(self, account_json):
        """
        Account update

        Args:
            account_json (str): Path to account json file

        """
        # TODO: Implement update operation
        raise NotImplementedError("Account update functionality is not implemented")


class DBAccount(Account):
    """
    Account operations for DB Deployment type
    """

    def create(self, config_root=None, account_json=None):
        """
        Account creation

        Args:
            config_root (str): Path to config root
            account_json (str): Path to account json file

        """
        # TODO: Implement create operation
        raise NotImplementedError("Account creation functionality is not implemented")

    def list(self, config_root=None):
        """
        Lists accounts

        Args:
            config_root (str): Path to config root

        """
        # TODO: Implement list operation
        raise NotImplementedError("Account list functionality is not implemented")

    def delete(self, config_root=None, account_json=None):
        """
        Account Deletion

        Args:
            config_root (str): Path to config root
            account_json (str): Path to account json file

        """
        # TODO: Implement delete operation
        raise NotImplementedError("Account delete functionality is not implemented")

    def update(self, account_json):
        """
        Account update

        Args:
            account_json (str): Path to account json file

        """
        # TODO: Implement update operation
        raise NotImplementedError("Account update functionality is not implemented")
