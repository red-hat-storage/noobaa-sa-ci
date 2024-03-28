"""
Utility functions to run on the remote machine that hosts the NSFS server

"""

import json
import logging
import os
import tempfile

from common_ci_utils.file_system_utils import compare_md5sums
from common_ci_utils.templating import Templating

from framework import config
from framework.ssh_connection_manager import SSHConnectionManager
from noobaa_sa import constants
from noobaa_sa.exceptions import MissingFileOrDirectory
from noobaa_sa.s3_client import S3Client

log = logging.getLogger(__name__)


def run_systemctl_command_on_nsfs_service(cmd):
    """
    Run a systemctl command on the NSFS service

    Args:
        cmd (str): The command to run (e.g. "status", "stop", "restart")

    Return:
        Tuple[int, str, str]: The return code, stdout and stderr of the command

    """
    return SSHConnectionManager().connection.exec_cmd(
        f"sudo systemctl {cmd} {constants.NSFS_SERVICE_NAME}"
    )


def get_nsfs_service_status():
    """
    Get the status of the NSFS service using systemctl

    Returns:
        str: The raw output of the systemctl status command

    """
    log.info("Getting the status of the NSFS service")
    _, stdout, _ = run_systemctl_command_on_nsfs_service("status")
    log.info(f"NSFS service status: {stdout}")
    return stdout


def is_nsfs_service_running():
    """
    Get the status of the NSFS service using systemctl

    Returns:
        bool: True if the NSFS service is running, False otherwise

    """
    status_str = get_nsfs_service_status()
    return "Active: active (running)" in status_str


def stop_nsfs_service():
    """
    Use systemctl to stop the NSFS service

    """
    log.info("Stopping the NSFS service")
    run_systemctl_command_on_nsfs_service("stop")


def restart_nsfs_service():
    """
    Use systemctl to restart the NSFS service

    """
    log.info("Restarting the NSFS service")
    run_systemctl_command_on_nsfs_service("restart")


def create_tls_key_and_cert(credentials_dir):
    """
    Create a TLS key and certificate for the NSFS server

    Args:
        credentials_dir (str): The full path to the credentials directory on the remote machine

    Returns:
        str: The full path to the TLS certificate file that was created

    """
    conn = SSHConnectionManager().connection

    log.info(
        f"Generating TLS key and certificate using openssl under {credentials_dir}"
    )

    # Create the TLS key
    conn.exec_cmd(f"sudo openssl genpkey -algorithm RSA -out {credentials_dir}/tls.key")

    # Create a SAN (Subject Alternative Name) configuration file to use with the CSR
    with tempfile.NamedTemporaryFile(mode="w+") as tmp_file:
        templating = Templating(base_path=config.ENV_DATA["template_dir"])
        account_template = "openssl_san.cnf"
        account_data_full = templating.render_template(
            account_template, data={"nsfs_server_ip": conn.host}
        )
        tmp_file.write(account_data_full)
        tmp_file.flush()
        conn.upload_file(tmp_file.name, "/tmp/openssl_san.cnf")

    # Create a CSR (Certificate Signing Cequest) file
    conn.exec_cmd(
        "sudo openssl req -new "
        f"-key {credentials_dir}/tls.key "
        f"-out {credentials_dir}/tls.csr "
        "-config /tmp/openssl_san.cnf "
        "-subj '/CN=localhost' "
    )

    # Use the TLS key and CSR to create a self-signed certificate
    conn.exec_cmd(
        "sudo openssl x509 -req -days 365 "
        f"-in {credentials_dir}/tls.csr "
        f"-signkey {credentials_dir}/tls.key "
        f"-out {credentials_dir}/tls.crt "
        "-extfile /tmp/openssl_san.cnf "
        "-extensions req_ext "
    )

    return f"{credentials_dir}/tls.crt"


def set_nsfs_certs_dir(creds_dir, config_root=config.ENV_DATA["config_root"]):
    """
    Edit the NSFS system.json file to specify the path to the TLS key and certificate

    Args:
        creds_dir (str): The full path to the credentials directory on the remote machine
        config_root(str): The full path to the configuration root directory on the remote machine

    Raises:
        MissingFileOrDirectoryException: In case the system.json file is not found under config_root

    """

    conn = SSHConnectionManager().connection
    log.info(
        "Editing the NSFS system.json file to specify the path to the TLS key and certificate"
    )
    retcode, stdout, _ = conn.exec_cmd(f"cat {config_root}/system.json")
    if retcode != 0:
        raise MissingFileOrDirectory(
            f"system.json file not found in {config_root}: {stdout}"
        )
    system_json = json.loads(stdout)
    system_json["nsfs_ssl_key_dir"] = creds_dir
    conn.exec_cmd(f"echo '{json.dumps(system_json)}' > {config_root}/system.json")


def setup_nsfs_tls_cert(config_root):
    """
    Configure the NSFS server TLS certification and download the certificate
    in a local file.

    Args:
        config_root (str): The path to the configuration root directory.

    """

    conn = SSHConnectionManager().connection
    remote_credentials_dir = f"{config_root}/certificates"

    # Create the TLS credentials and configure the NSFS service to use them
    conn.exec_cmd(f"sudo mkdir -p {remote_credentials_dir}")
    remote_tls_crt_path = create_tls_key_and_cert(remote_credentials_dir)
    set_nsfs_certs_dir(remote_credentials_dir, config_root)
    restart_nsfs_service()

    # Download the certificate to a local file
    with tempfile.NamedTemporaryFile(
        prefix="tls_", suffix=".crt", delete=False
    ) as local_tls_crt_file:
        conn.download_file(
            remotepath=remote_tls_crt_path,
            localpath=local_tls_crt_file.name,
        )

    S3Client.static_tls_crt_path = local_tls_crt_file.name


def check_nsfs_tls_cert_setup(config_root):
    """
    Check whether the CI has the NSFS server TLS certificate.

    Args:
        config_root (str): The full path of the configuration root directory.

    Returns:
        bool: True if the local and remote TLS certificates exist and are identical,
              False otherwise.

    """
    conn = SSHConnectionManager().connection

    # Check if the local TLS certificate file exists
    if not hasattr(S3Client, "static_tls_crt_path"):
        log.info("Local NSFS server TLS certificate path was yet stored")
        return False

    if not os.path.exists(S3Client.static_tls_crt_path):
        log.info(
            f"The local NSFS server TLS certificate was not found under {S3Client.static_tls_crt_path}"
        )
        return False

    # Check if a TLS certificate file exists on the remote machine under the config root
    retcode, _, _ = conn.exec_cmd(f"[ -d '{config_root}/certificates/tls.crt/' ]")
    if retcode != 0:
        log.info(
            f"NSFS server TLS certificate was not found under {config_root}/certificates"
        )
        return False

    with tempfile.TemporaryDirectory() as tmp_dir:
        local_tls_crt_file = f"{tmp_dir}/tls.crt"
        conn.download_file(
            remotepath=f"{config_root}/certificates/tls.crt",
            localpath=f"{tmp_dir}/tls.crt",
        )
        return compare_md5sums(local_tls_crt_file, S3Client.static_tls_crt_path)
