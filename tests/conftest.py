import logging
import pytest
import uuid

from common_ci_utils.command_runner import exec_cmd
from noobaa_sa.factories import AccountFactory
from noobaa_sa.bucket import BucketManager


log = logging.getLogger(__name__)


@pytest.fixture
def account_manager(account_json=None):
    account_factory = AccountFactory()
    return account_factory.get_account(account_json)


@pytest.fixture
def bucket_manager(request):
    bucket_manager = BucketManager()
    # TODO: Implement cleanup operation
    """
    def bucket_cleanup():
      for bucket in bucket_manager.list():
        bucket_manager.delete(bucket)
        
    request.addfinalizer(bucket_cleanup)
    """
    return bucket_manager


@pytest.fixture
def unique_resource_name(request):
    """
    Generates a unique resource name with the given prefix
    """

    def _get_unique_name(prefix="resource"):
        unique_id = str(uuid.uuid4()).split("-")[0]
        return f"{prefix}-{unique_id}"

    return _get_unique_name


@pytest.fixture(scope="function")
def random_hex(request):
    """
    Generates a random hexadecimal string.
    """

    def _get_random_hex():
        cmd = "openssl rand -hex 20"
        completed_process = exec_cmd(cmd)
        stdout = completed_process.stdout
        return stdout.decode("utf-8").strip()

    return _get_random_hex
