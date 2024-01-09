import logging

log = logging.getLogger(__name__)


def test_bucket_operations(account_manager, bucket_manager, unique_resource_name, random_hex):
    # Bucket operations
    account_name = unique_resource_name(prefix="account")
    access_key = random_hex()
    secret_key = random_hex()
    account_manager.create(account_name, access_key, secret_key)
    account_manager.list()
    bucket_name = unique_resource_name(prefix="bucket")
    bucket_manager.create(account_name, bucket_name)
    bucket_manager.list()
    bucket_manager.delete(bucket_name)
    log.info(account_name)
    account_manager.delete(account_name)
    account_manager.list()
