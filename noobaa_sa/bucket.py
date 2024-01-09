"""
Module which contain bucket operations like create, delete, list and update
"""

import logging
import re

from framework import config
from framework.connection import SSHConnection
from noobaa_sa.defaults import MANAGE_NSFS
import noobaa_sa.exceptions as e

log = logging.getLogger(__name__)


class BucketManager:
    """
    Bucket operations
    """
    def __init__(self):
        """
        Initialize necessary variable
        """
        self.manage_nsfs = MANAGE_NSFS
        self.config_root = config.ENV_DATA["config_root"]
        self.conn = SSHConnection().connection

    def create(self, account_name, bucket_name, config_root=None):
        """
        Create bucket using CLI

        Args:
            account_name: User name
            bucket_name: Name of the bucket
            config_root (str): Path to config root
        """
        unwanted_log = "2>/dev/null"
        base_cmd = f"sudo /usr/local/noobaa-core/bin/node {self.manage_nsfs}"
        if config_root is None:
            config_root = self.config_root
        log.info("Gather user info before creating bucket")
        cmd = f"{base_cmd} account status --config_root {config_root} --name {account_name} {unwanted_log}"
        retcode, stdout, stderr = self.conn.exec_cmd(cmd)
        log.info(retcode)
        if retcode != 0:
            raise e.AccountStatusFailed(
                f"Failed to get status of account {stderr}"
            )
        account_info = re.findall(r'\{([^}]+)\}', stdout)
        pattern = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        account_info = account_info[0].strip()
        account_info = pattern.sub('', account_info)
        account_info = account_info.replace("'","")
        account_info_param = account_info.split(", ")
        account_dict = {}
        for item in account_info_param:
            key, value = item.split(':')
            account_dict[key.strip()] = value.strip()
        account_email = str(account_dict['email'])
        bucket_path = str(account_dict['new_buckets_path'])

        cmd = f"{base_cmd} bucket add --config_root {config_root} --name {bucket_name} --email {account_email} --path {bucket_path} {unwanted_log}"
        retcode, stdout, stderr = self.conn.exec_cmd(cmd)
        if retcode != 0:
            raise e.BucketCreationFailed(
                f"Failed to create bucket {stderr}"
            )
        log.info("Bucket created successfully")


    def list(self, config_root=None):
        """
        Lists Buckets

        Args:
            config_root (str): Path to config root
        """
        if config_root is None:
            config_root = self.config_root
        log.info("Listing available buckets")
        cmd = f"sudo /usr/local/noobaa-core/bin/node {self.manage_nsfs} bucket list --config_root {config_root}"
        retcode, stdout, stderr = self.conn.exec_cmd(cmd)
        if retcode != 0:
            raise e.BucketListFailed(f"Listing of buckets failed with error {stderr}")
        log.info(stdout)


    def delete(self, bucket_name, config_root=None):
        """
        Bucket Deletion

        Args:
            bucket_name (str): Bucket to be deleted
            config_root (str): Path to config root
        """
        if config_root is None:
            config_root = self.config_root
        log.info(f"Deleting {bucket_name} Bucket from NSFS")
        cmd = f"sudo /usr/local/noobaa-core/bin/node {self.manage_nsfs} bucket delete --name {bucket_name} --config_root {config_root}"
        retcode, stdout, stderr = self.conn.exec_cmd(cmd)
        if retcode != 0:
            raise e.BucketDeletionFailed(f"Deleting bucket failed with error {stderr}")
        
        log.info(stdout)
        log.info("Bucket deleted successfully")


    def update(self, bucket_name):
        """
        Bucket update

        Args:
            bucket_name (str): Bucket name to be updated

        """
        # TODO: Implement update operation
        raise NotImplementedError("Bucket update functionality is not implemented")
