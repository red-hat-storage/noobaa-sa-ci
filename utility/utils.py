"""
This module contains various common utility function which are used across project
"""
import logging
import os
import shlex
import socket
import subprocess
from utility.exceptions import RPMInstallationFailed, PermissionsFailedToChange

log = logging.getLogger(__name__)


def install_rpm(rpm_path=None, packages=None):
    """
    Install RPMS/packages

    Args:
        rpm_path (str): RPM path to install
        packages (list): List of packages to install

    """
    target_to_install = rpm_path if rpm_path else " ".join(map(str, packages))
    log.info(f"Installing {target_to_install}")
    cmd = f"yum install {target_to_install} -y"
    result = exec_cmd(cmd, use_sudo=True)
    if result.returncode == 0:
        log.info(f"Successfully installed {rpm_path}")
    else:
        raise RPMInstallationFailed(f"Error installing {rpm_path}:\n{result.stderr}")


def enable_postgresql_version(version):
    """
    Enable postgresql version

    Args:
        version (int): postresql version to enable

    """
    log.info(f"Enable the module stream for Postgres version to {version}")
    cmd = f"sudo dnf module enable postgresql:{version}"
    exec_cmd(cmd)


def exec_cmd(
    cmd,
    timeout=600,
    silent=False,
    use_sudo=False,
    **kwargs,
):
    """
    Run an arbitrary command locally

    If the command is grep and matching pattern is not found, then this function
    returns "command terminated with exit code 1" in stderr.

    Args:
        cmd (str): command to run
        timeout (int): Timeout for the command, defaults to 600 seconds.
        silent (bool): If True will silent errors from the server, default false
        use_sudo (bool): If True cmd will be executed with sudo

    Raises:
        CommandFailed: In case the command execution fails

    Returns:
        (CompletedProcess) A CompletedProcess object of the command that was executed
        CompletedProcess attributes:
        returncode (str): The exit code of the process, negative for signals.
        stdout     (str): The standard output (None if not captured).
        stderr     (str): The standard error (None if not captured).

    """
    if use_sudo:
        cmd = f"sudo {cmd}"
    log.info(f"Executing command: {cmd}")
    if isinstance(cmd, str) and not kwargs.get("shell"):
        cmd = shlex.split(cmd)
    completed_process = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        timeout=timeout,
        **kwargs,
    )
    if len(completed_process.stdout) > 0:
        log.info(f"Command stdout: {completed_process.stdout.decode()}")
    else:
        log.info("Command stdout is empty")

    if len(completed_process.stderr) > 0:
        if not silent:
            log.info(f"Command stderr: {completed_process.stderr.decode()}")
    else:
        log.info("Command stderr is empty")
    log.info(f"Command return code: {completed_process.returncode}")
    return completed_process


def create_directory(name):
    """
    Creates directory

    Args:
        name (str): Name of directory to create

    """
    # Check if the directory already exists
    if not os.path.exists(name):
        # Create the directory with permissions
        os.makedirs(name, mode=0o777)
        log.info(f"Directory '{name}' created successfully.")
    else:
        log.info(f"Directory '{name}' already exists.")


def set_permissions(directory_path, permissions, use_sudo=False):
    """
    Sets permissions to directory

    Args:
        directory_path (str): Name of the directory to give required permissions
        permissions (int): permissions to set on directory. permissions must be in
            octal notation. For example, 755 grants read, write, and execute
            permissions to the owner and read and execute permissions to the group and others
        use_sudo (bool): If True cmd will be executed with sudo

    """
    cmd = f"chmod {permissions} {directory_path}"
    result = exec_cmd(cmd=cmd, use_sudo=use_sudo)
    if result.returncode == 0:
        log.info(f"Permissions for '{directory_path}' have been set to {permissions}")
    else:
        raise PermissionsFailedToChange(
            f"Error setting permissions for '{directory_path}': {result.stderr}"
        )


def get_hostname():
    """
    Fetches hostname

    Returns:
        str: Hostname

    """
    return socket.gethostname()


def get_ip_address():
    """
    Fetches IP address

    Returns:
        str: IP address

    """
    hostname = get_hostname()
    return socket.gethostbyname(hostname)
