"""
Module which contain bucket operations like create, delete, list, status and update
"""

import json
import logging

from framework import config
from framework.ssh_connection_manager import SSHConnectionManager
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
        self.base_cmd = f"sudo /usr/local/noobaa-core/bin/node {self.manage_nsfs}"
        self.unwanted_log = "2>/dev/null"
        self.conn = SSHConnectionManager().connection

    def create(self, account_name, bucket_name, config_root=None):
        """
        Create bucket using CLI

        Args:
            account_name: User name
            bucket_name: Name of the bucket
            config_root (str): Path to config root
        """
        if config_root is None:
            config_root = self.config_root
        log.info("Gather user info before creating bucket")
        cmd = f"{self.base_cmd} account status --config_root {config_root} --name {account_name} {self.unwanted_log}"
        retcode, stdout, stderr = self.conn.exec_cmd(cmd)
        if retcode != 0:
            raise e.AccountStatusFailed(f"Failed to get status of account {stderr}")
        log.info(stdout)
        account_info = json.loads(stdout)
        account_email = account_info["response"]["reply"]["email"]
        bucket_path = account_info["response"]["reply"]["nsfs_account_config"][
            "new_buckets_path"
        ]
        cmd = f"{self.base_cmd} bucket add --config_root {config_root} --name {bucket_name} --email {account_email} --path {bucket_path} {self.unwanted_log}"
        retcode, stdout, stderr = self.conn.exec_cmd(cmd)
        if retcode != 0:
            raise e.BucketCreationFailed(f"Failed to create bucket {stderr}")
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
        cmd = f"{self.base_cmd} bucket list --config_root {config_root}"
        retcode, stdout, stderr = self.conn.exec_cmd(cmd)
        if retcode != 0:
            raise e.BucketListFailed(f"Listing of buckets failed with error {stderr}")
        bucket_ls = json.loads(stdout)
        bucket_ls = bucket_ls["response"]["reply"]
        bucket_list = [item["name"] for item in bucket_ls]
        log.info(bucket_list)
        return bucket_list

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
        cmd = f"{self.base_cmd} bucket delete --name {bucket_name} --config_root {config_root}"
        retcode, stdout, stderr = self.conn.exec_cmd(cmd)
        if retcode != 0:
            raise e.BucketDeletionFailed(f"Deleting bucket failed with error {stderr}")
        log.info(stdout)
        log.info("Bucket deleted successfully")

    def update(self, bucket_name, config_root=None, **kwargs):
        """
        Bucket update

        Args:
            bucket_name (str): Bucket name to be updated
            config_root (str): Path to config root

            Supported update options via kwargs (based on https://url.corp.redhat.com/dd8609e):
            new_name (str): Update the bucket name
            email (str): Update the bucket owner email
            path (str): Update the bucket path
            bucket_policy (str): Update bucket policy with the valid JSON policy, or unset with ""
            fs_backend_type (str): Update filesystem type to "GPFS", CEPH_FS", "NFSv4" or or unset with ""

        Example usage:
            bucket_manager.update(bucket_name, new_name=new_bucket_name, path=new_bucket_path)
        """
        if config_root is None:
            config_root = self.config_root
        self.update_data = kwargs
        update_cmd = ""
        if "new_name" in self.update_data:
            update_cmd = update_cmd + f"--new_name {self.update_data.get('new_name')} "
        if "path" in self.update_data:
            update_cmd = update_cmd + f"--path {self.update_data.get('path')} "
        log.info(f'Updating the bucket "{bucket_name}"')
        cmd = f"{self.base_cmd} bucket update --name {bucket_name} {update_cmd} --config_root {config_root} {self.unwanted_log}"
        retcode, stdout, stderr = self.conn.exec_cmd(cmd)
        if retcode != 0:
            raise e.BucketUpdateFailed(
                f'Failed to update bucket "{bucket_name}" with error {stderr}'
            )
        log.info(stdout)
        log.info("Bucket info updated successfully")
        # TODO: Implement --bucket_policy update operation
        # TODO: Implement --fs_backend update operation
        # TODO: Implement --email update operation

    def status(self, bucket_name, config_root=None):
        """
        Bucket status

        Args:
            bucket_name (str): Bucket name
            config_root (str): Path to config root

        Returns:
            dict: Dictionary of bucket response
        """
        if config_root is None:
            config_root = self.config_root
        log.info(f'Getting status of the bucket "{bucket_name}"')
        cmd = f"{self.base_cmd} bucket status --name {bucket_name} --config_root {config_root} {self.unwanted_log}"
        retcode, stdout, stderr = self.conn.exec_cmd(cmd)
        if retcode != 0:
            raise e.BucketStatusFailed(
                f'Failed to get the status of bucket "{bucket_name}" with error {stderr}'
            )
        log.info(stdout)
        return json.loads(stdout)
