"""
Module to connect to remote host
"""

import logging

from common_ci_utils.connection import Connection
from framework import config
from paramiko.auth_handler import AuthenticationException, SSHException

log = logging.getLogger(__name__)


class SSHConnectionManager:
    """
    A class that connects to remote host
    """

    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(SSHConnectionManager, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        """
        Get connection to host

        Raises:
            authException: In-case of authentication failed
            sshException: In-case of ssh connection failed

        """
        # Initialize the connection only if it hasn't been created yet
        self._conn = None
        self.host = config.ENV_DATA["noobaa_sa_host"]
        self.user = config.ENV_DATA["user"]
        self.password = config.ENV_DATA.get("password")
        self.private_key = config.ENV_DATA.get("private_key")

    @property
    def connection(self):
        """
        Get connection to host

        Returns:
            paramiko.client: Paramiko SSH client connection to host

        """
        if self._conn:
            return self._conn

        try:
            if self.private_key:
                self._conn = Connection(
                    host=self.host,
                    user=self.user,
                    private_key=self.private_key,
                )
            else:
                self._conn = Connection(
                    host=self.host,
                    user=self.user,
                    password=self.password,
                )
        except AuthenticationException as authException:
            log.error(f"Authentication failed: {authException}")
            raise authException
        except SSHException as sshException:
            log.error(f"SSH connection failed: {sshException}")
            raise sshException

        return self._conn

    @classmethod
    def close_connection(cls):
        """
        Closes SSH connection
        """
        if cls._instance and cls._instance._conn:
            cls._instance._conn.close()
            cls._instance = None


def pytest_sessionfinish(session, exitstatus):
    # Close the SSH connection at the end of the pytest session
    SSHConnectionManager.close_connection()
