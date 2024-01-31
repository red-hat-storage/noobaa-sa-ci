import logging
import os

from framework.ssh_connection_manager import SSHConnectionManager
from utility.utils import (
    get_noobaa_sa_host_home_path,
    generate_random_hex,
    generate_unique_resource_name,
)

log = logging.getLogger(__name__)


def test_bucket_operations(account_manager, bucket_manager):
    # Create SSH connection
    conn = SSHConnectionManager().connection
    # Bucket operations
    account_name = generate_unique_resource_name(prefix="account")
    access_key = generate_random_hex()
    secret_key = generate_random_hex()
    account_manager.create(account_name, access_key, secret_key)
    account_manager.list()
    bucket_name = generate_unique_resource_name(prefix="bucket")
    bucket_manager.create(account_name, bucket_name)
    bucket_list = bucket_manager.list()
    bucket_manager.status(bucket_name)
    new_bucket_name = generate_unique_resource_name(prefix="bucket")
    bucket_manager.update(bucket_name, new_name=new_bucket_name)
    # Update bucket name with original name
    log.info("Changing bucket name back to original name")
    bucket_manager.update(new_bucket_name, new_name=bucket_name)
    # TODO Add email update operation
    """email= ""
    bucket_manager.update(bucket_name, email=new_bucket_name)
    """
    # Create new bucket path for update operation
    hd = get_noobaa_sa_host_home_path()
    new_bucket_path = os.path.join(hd, f"new_fs_{account_name}")
    cmd = f"sudo mkdir {new_bucket_path}"
    conn.exec_cmd(cmd)
    bucket_manager.update(bucket_name, path=new_bucket_path)
    bucket_manager.delete(bucket_name)
    log.info(account_name)
    account_manager.delete(account_name)
    account_manager.list()
