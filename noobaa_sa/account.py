"""
Module which contain account operations like create, delete, list and update
"""

import json
import logging
import os
import tempfile
from abc import ABC, abstractmethod

from common_ci_utils.random_utils import generate_unique_resource_name
from common_ci_utils.templating import Templating

from framework import config
from framework.ssh_connection_manager import SSHConnectionManager
from noobaa_sa import constants
from noobaa_sa.defaults import MANAGE_NSFS
from noobaa_sa.exceptions import (
    AccountCreationFailed,
    AccountDeletionFailed,
    AccountListFailed,
    AccountStatusQueryFailed,
    AccountUpdateFailed,
)
from utility.utils import generate_random_key, get_noobaa_sa_host_home_path

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
        account_name="",
        access_key="",
        secret_key="",
        config_root=None,
        fs_backend=constants.DEFAULT_FS_BACKEND,
        allow_bucket_creation=True,
    ):
        """
        Account creation using file

        Args:
            account_name (str): name of the account
            access_key (str): access key for the account
            secret_key (str): secret key for the account
            config_root (str): path to config root
            fs_backend (str): filesystem backend
            allow_bucket_creation (bool): allow bucket creation

        Returns:
            tuple:
                account_name (str): name of the account
                access_key (str): access key for the account
                secret_key (str): secret key for the account

                If account_name, access_key and secret_key are not provided,
                default values will be generated and returned

        """

        # Set default values if not provided
        if not account_name:
            account_name = generate_unique_resource_name(prefix="account")
        if not access_key:
            access_key = generate_random_key(constants.EXPECTED_ACCESS_KEY_LEN)
        if not secret_key:
            secret_key = generate_random_key(constants.EXPECTED_SECRET_KEY_LEN)

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
            "access_key": access_key,
            "secret_key": secret_key,
            "bucket_path": bucket_path,
            "fs_backend": fs_backend,
            "allow_bucket_creation": allow_bucket_creation,
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
        cmd = f"sudo {self.manage_nsfs} account add --config_root {config_root} --from_file {account_file.name}"
        retcode, stdout, _ = self.conn.exec_cmd(cmd)
        if retcode != 0:
            raise AccountCreationFailed(
                f"Creation of account failed with error {stdout}"
            )
        log.info("Account created successfully")
        return account_name, access_key, secret_key

    def create_anonymous(self, uid=None, gid=None, user=None):
        """
        Create an anonymous account using the NooBaa CLI

        Args:
            uid (str|optional): uid of an account with access to the file system
            gid (str|optional): gid of an account with access to the file system
            user (str|optional): user name of an account with access to the file system

            Note that either a valid uid and gid pair or a valid user name must be provided

        Raises:
            AccountCreationFailed: If the creation of the anonymous account fails

        """

        log.info(f"Adding anonymous account: uid: {uid}, gid: {gid}, user: {user}")

        cmd = f"sudo {self.manage_nsfs} account add --anonymous"
        if uid is not None and gid is not None:
            cmd += f" --uid {uid} --gid {gid}"
        elif user:
            cmd += f" --user {user}"
        else:
            raise AccountCreationFailed(
                "Please provide either a valid uid and gid pair, or a valid user name"
            )

        retcode, stdout, _ = self.conn.exec_cmd(cmd)
        if retcode != 0:
            raise AccountCreationFailed(
                f"Creation of anonymous account failed with error {stdout}"
            )
        log.info("Anonymous account created successfully")

    def list(self, config_root=None):
        """
        Lists accounts

        Args:
            config_root (str): Path to config root

        """
        if config_root is None:
            config_root = self.config_root
        log.info("Listing accounts for NSFS deployment")
        cmd = f"sudo {self.manage_nsfs} account list --config_root {config_root}"
        retcode, stdout, _ = self.conn.exec_cmd(cmd)
        log.info(stdout)
        if retcode != 0:
            raise AccountListFailed(f"Listing of accounts failed with error {stdout}")
        account_ls = json.loads(stdout)
        account_ls = account_ls["response"]["reply"]
        account_list = [item["name"] for item in account_ls]
        log.info(account_list)
        return account_list

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
        cmd = f"sudo {self.manage_nsfs} account delete "
        if account_name != "anonymous":
            cmd += f"--name {account_name} --config_root {config_root}"
        else:
            cmd += f"--anonymous"

        retcode, stdout, _ = self.conn.exec_cmd(cmd)
        if retcode != 0:
            raise AccountDeletionFailed(f"Deleting account failed with error {stdout}")

    def update(self, account_name, update_params, config_root=None):
        """
        Account update

        Args:
            account_name (str): name of the account
            update_params (dict): dictionary containing the parameters to be updated
                                  and their new values
            config_root (str): path to config root

        """
        if config_root is None:
            config_root = self.config_root

        cmd = f"sudo {self.manage_nsfs} account"
        if account_name != "anonymous":
            cmd += f" update --name {account_name}"
        else:
            cmd += " update --anonymous"
        for key, new_value in update_params.items():
            # Convert boolean values to the expected string format
            if isinstance(new_value, bool):
                new_value = str(new_value).lower()
            cmd += f" --{key} {new_value}"

        if account_name != "anonymous":
            cmd += f" --config_root {config_root}"

        retcode, stdout, _ = self.conn.exec_cmd(cmd)
        if retcode != 0:
            raise AccountUpdateFailed(f"Updating account failed with error {stdout}")

    def status(self, account_name, config_root=None):
        """
        Get the config data of a given account

        Args:
            account_name (str): name of the account
            config_root (str): path to config root

        Returns:
            dict: The config data of the account

        """
        if config_root is None:
            config_root = self.config_root

        cmd = f"sudo {self.manage_nsfs} account status"
        if account_name != "anonymous":
            cmd += f" --name {account_name} --show_secrets"
            cmd += f" --config_root {config_root}"
        else:
            cmd += " --anonymous"

        retcode, stdout, _ = self.conn.exec_cmd(cmd)
        if retcode != 0:
            raise AccountStatusQueryFailed(
                f"Getting account status failed with error {stdout}"
            )

        response_dict = json.loads(stdout)
        return response_dict["response"]["reply"]


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
