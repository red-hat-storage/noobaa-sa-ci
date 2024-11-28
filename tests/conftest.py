import os
import logging
import random
import string
import tempfile
import pytest

from common_ci_utils.command_runner import exec_cmd
from datetime import datetime
from common_ci_utils.random_utils import (
    generate_random_hex,
    generate_unique_resource_name,
)
from framework.ssh_connection_manager import SSHConnectionManager
from noobaa_sa import constants
from noobaa_sa.exceptions import AccountDeletionFailed
from noobaa_sa.factories import AccountFactory
from noobaa_sa.bucket import BucketManager
from framework import config
from noobaa_sa.s3_client import S3Client
from utility.retry import retry_until_timeout
from utility.utils import (
    get_env_config_root_full_path,
    get_current_test_name,
    get_noobaa_sa_host_home_path,
    is_linux_username_available,
    is_uid_gid_available,
    get_noobaa_sa_rpm_name,
    get_noobaa_sa_version_string,
)
from utility.nsfs_server_utils import (
    get_system_json,
    restart_nsfs_service,
    check_nsfs_tls_cert_setup,
    setup_nsfs_tls_cert,
)


log = logging.getLogger(__name__)


@pytest.fixture(scope="class")
def account_manager_class(request, account_json=None):
    return account_manager_implementation(request, account_json)


@pytest.fixture
def account_manager(request, account_json=None):
    return account_manager_implementation(request, account_json)


def account_manager_implementation(request, account_json=None):
    account_factory = AccountFactory()
    acc_manager_instance = account_factory.get_account(account_json)

    def cleanup():
        """
        Make sure to delete the created account abd buckets
        """
        try:
            bucket_manager = BucketManager()
            for bucket in bucket_manager.list():
                bucket_manager.delete(bucket, force=True)
            for acc in acc_manager_instance.list():
                acc_manager_instance.delete(account_name=acc)
            acc_manager_instance.delete(account_name="anonymous")
        except AccountDeletionFailed as e:
            log.warning(f"Failed to delete anonymous account: {e}")

    request.addfinalizer(cleanup)
    return acc_manager_instance


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

        # Wait for the NSFS service to create the system.json under the new config root
        retry_until_timeout(get_system_json, timeout=60, config_root=config_root)

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


@pytest.fixture(scope="function")
def linux_user_factory(request):
    """
    Factory for creating random Linux users on the remote machine, and cleanup after the test.

    Returns:
        func: A function that creates a random Linux user.

    """
    conn = SSHConnectionManager().connection
    created_groups = []
    created_users = []

    def _create_user():
        """
        Create a random Linux user on the remote machine

        Returns:
            tuple: A tuple containing the UID, GID, and username of the created user.

        """

        def _random_username():
            """Generate a random string of fixed length."""
            letters = string.ascii_lowercase
            return "".join(random.choice(letters) for i in range(8))

        def _random_uid_gid():
            """Generate a random UID and GID between 1000 and 9999."""
            return random.randint(1000, 9999), random.randint(1000, 9999)

        # Generate until available credentials are found
        username = _random_username()
        while not is_linux_username_available(username):
            username = _random_username()

        uid, gid = _random_uid_gid()
        while not is_uid_gid_available(uid, gid):
            uid, gid = _random_uid_gid()

        # Create the group
        group_name = f"group_{username}"
        create_group_cmd = f"sudo groupadd -g {gid} {group_name}"
        retcode, stdout, _ = conn.exec_cmd(create_group_cmd)
        if retcode != 0:
            raise ValueError(f"Failed to create group: {stdout}")
        created_groups.append(group_name)

        # Create the user
        create_cmd = f"sudo useradd -u {uid} -g {gid} {username}"
        retcode, stdout, _ = conn.exec_cmd(create_cmd)
        if retcode != 0:
            raise ValueError(f"Failed to create user: {stdout}")
        created_users.append(username)

        return uid, gid, username

    def _cleanup():
        # Delete the created users
        for user_name in created_users:
            delete_cmd = f"sudo userdel {user_name}"
            retcode, stdout, _ = conn.exec_cmd(delete_cmd)
            if retcode != 0:
                raise ValueError(f"Failed to delete user: {stdout}")

        # Delete the created groups
        for group in created_groups:
            delete_group_cmd = f"sudo groupdel {group}"
            retcode, stdout, _ = conn.exec_cmd(delete_group_cmd)
            if retcode != 0:
                raise ValueError(f"Failed to delete group: {stdout}")

    request.addfinalizer(_cleanup)
    return _create_user


@pytest.fixture(scope="session", autouse=True)
def testsuite_properties(record_testsuite_property, pytestconfig):
    """
    Configures custom testsuite properties for junit xml
    """
    noobaa_sa_rpm_name = get_noobaa_sa_rpm_name()
    noobaa_sa_version_string_x_y_z = get_noobaa_sa_version_string(noobaa_sa_rpm_name)
    noobaa_sa_version_string_x_y = ".".join(
        get_noobaa_sa_version_string(noobaa_sa_rpm_name).split(".")[:2]
    )
    record_testsuite_property("rp_launch_url", config.REPORTING.get("rp_launch_url"))
    record_testsuite_property("rp_launch_name", noobaa_sa_version_string_x_y)
    record_testsuite_property("rp_rpm_version", noobaa_sa_version_string_x_y_z)
    record_testsuite_property("rp_rpm_name", noobaa_sa_rpm_name)
    record_testsuite_property(
        f"rp_launch_description",
        f"Job name:{noobaa_sa_rpm_name}\n{config.RUN.get('jenkins_build_url')}",
    )

