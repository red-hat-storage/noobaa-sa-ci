import os
import logging
import tempfile
import pytest

from common_ci_utils.command_runner import exec_cmd
from common_ci_utils.random_utils import (
    generate_random_hex,
    generate_unique_resource_name,
)
from framework.ssh_connection_manager import SSHConnectionManager
from noobaa_sa import constants
from noobaa_sa.factories import AccountFactory
from noobaa_sa.bucket import BucketManager
from framework import config
from noobaa_sa.s3_client import S3Client
from utility.utils import (
    get_env_config_root_full_path,
    get_current_test_name,
    get_noobaa_sa_host_home_path,
)
from utility.nsfs_server_utils import (
    restart_nsfs_service,
    check_nsfs_tls_cert_setup,
    setup_nsfs_tls_cert,
)


log = logging.getLogger(__name__)


@pytest.fixture(scope="class")
def account_manager_class(account_json=None):
    return account_manager_implementation(account_json)


@pytest.fixture
def account_manager(account_json=None):
    return account_manager_implementation(account_json)


def account_manager_implementation(account_json=None):
    account_factory = AccountFactory()
    return account_factory.get_account(account_json)


@pytest.fixture
def bucket_manager(request):
    bucket_manager = BucketManager()

    def bucket_cleanup():
        for bucket in bucket_manager.list():
            bucket_manager.delete(bucket, force=True)

    request.addfinalizer(bucket_cleanup)
    return bucket_manager


@pytest.fixture(scope="session")
def set_nsfs_server_config_root(request):
    """
    Returns a function that allows
    configuring the NSFS service to use a custom config root dir

    """
    conn = SSHConnectionManager().connection

    # Ensure to reset to the default config root on teardown
    def _clear_config_dir_redirect():
        conn.exec_cmd("sudo rm -f /etc/noobaa.conf.d/config_dir_redirect")
        restart_nsfs_service()

    def _redirect_nsfs_service_to_use_custom_config_root(config_root):
        """
        Configure the NSFS service to use a custom config root dir

        Args:
            config_root (str): The full path to the configuration root directory on the remote machine

        """

        # Skip if the provider config is the default just clear the config root redirect
        if config_root == constants.DEFAULT_CONFIG_ROOT_PATH:
            _clear_config_dir_redirect()
            return

        # Skip if the provided config root path is already set
        retcode, stdout, _ = conn.exec_cmd("cat /etc/noobaa.conf.d/config_dir_redirect")
        if retcode == 0 and stdout.strip() == config_root:
            return

        # Make sure the provided config root path exists on the remote machine
        retcode, _, _ = conn.exec_cmd(f"sudo mkdir -p {config_root}")
        if retcode != 0:
            raise FileNotFoundError(
                "Failed to create the provided config root path on the remote machine"
            )

        conn.exec_cmd(
            f"echo '{config_root}' | sudo tee /etc/noobaa.conf.d/config_dir_redirect"
        )
        restart_nsfs_service()

    request.addfinalizer(_clear_config_dir_redirect)
    return _redirect_nsfs_service_to_use_custom_config_root


@pytest.fixture(scope="class")
def s3_client_factory_class(set_nsfs_server_config_root, account_manager_class):
    """
    Class scoped factory to create S3Client instances with given credentials.

    Args:
        set_nsfs_server_config_root (fixture): The prerequisite fixture to setup the NSFS server TLS certificate.
        account_manager (AccountManager): The account manager instance.

    Returns:
        func: A function that creates S3Client instances.

    """
    return s3_client_factory_implementation(
        set_nsfs_server_config_root, account_manager_class
    )


@pytest.fixture(scope="function")
def s3_client_factory(set_nsfs_server_config_root, account_manager):
    """
    Function scoped factory to create S3Client instances with given credentials.

    Args:
        set_nsfs_server_config_root (fixture): The prerequisite fixture to setup the NSFS server TLS certificate.
        account_manager (AccountManager): The account manager instance.

    Returns:
        func: A function that creates S3Client instances.

    """
    return s3_client_factory_implementation(
        set_nsfs_server_config_root, account_manager
    )


def s3_client_factory_implementation(set_nsfs_server_config_root, account_manager):
    """
    Factory to create S3Client instances with given credentials.

    Args:
        account_manager (AccountManager): The account manager instance.

    Returns:
        func: A function that creates S3Client instances.

    """

    def create_s3client(
        endpoint_port=constants.DEFAULT_NSFS_PORT,
        access_and_secret_keys_tuple=None,
        verify_tls=True,
        config_root=None,
    ):
        """
        Create an S3Client instance using the given credentials.

        Args:
            endpoint_port (int): The port to use for the endpoint.
            access_and_secret_keys_tuple (tuple): A tuple of access and secret keys.
            verify_tls (bool): Whether to verify the TLS certificate.

        Returns:
            S3Client: An S3Client instance.

        """
        if not config_root:
            config_root = get_env_config_root_full_path()

        # The following setup requires the full path of the config root
        if config_root.startswith("~/"):
            config_root = (
                f'{get_noobaa_sa_host_home_path()}/{config_root.split("~/")[1]}'
            )

        set_nsfs_server_config_root(config_root)

        if not check_nsfs_tls_cert_setup(config_root):
            setup_nsfs_tls_cert(config_root)

        # Set the AWS access and secret keys
        if access_and_secret_keys_tuple is None:
            _, access_key, secret_key = account_manager.create()
        else:
            access_key, secret_key = access_and_secret_keys_tuple

        nb_sa_host_address = config.ENV_DATA["noobaa_sa_host"]
        return S3Client(
            endpoint=f"https://{nb_sa_host_address}:{endpoint_port}",
            access_key=access_key,
            secret_key=secret_key,
            verify_tls=verify_tls,
        )

    return create_s3client


@pytest.fixture(scope="function")
def s3client(s3_client_factory):
    """
    Create an S3Client using the credentials of a new account.

    Returns:
        S3Client: An S3Client instance.

    """
    return s3_client_factory()


@pytest.fixture(scope="class")
def c_scope_s3client(s3_client_factory_class):
    """
    Create an S3Client using the credentials of a new account - class scoped.

    Returns:
        S3Client: An S3Client instance.

    """
    return s3_client_factory_class()


@pytest.fixture()
def tmp_directories_factory(request):
    """
    Factory to create temporary local testing directories, and cleanup after the test.

    """
    random_hex = generate_random_hex(5)
    current_test_name = get_current_test_name()
    tmp_testing_dirs_root = f"/tmp/{current_test_name}-{random_hex}"
    os.mkdir(tmp_testing_dirs_root)

    def create_tmp_testing_dirs(dirs_to_create):
        """
        Create temporary local testing directories.

        Args:
            dirs_to_create (list): List of directories to create.

        """
        created_dirs_paths = []
        for dir in dirs_to_create:
            new_tmp_dir_path = f"{tmp_testing_dirs_root}/{dir}"
            os.mkdir(new_tmp_dir_path)
            created_dirs_paths.append(new_tmp_dir_path)

        return created_dirs_paths

    def cleanup():
        """
        Cleanup local test directories.

        """
        exec_cmd(f"rm -rf {tmp_testing_dirs_root}")

    request.addfinalizer(cleanup)
    return create_tmp_testing_dirs
