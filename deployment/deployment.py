import logging
import os
import requests
import tempfile
import time
from deployment.npm import NPM
from framework import config
from utility.templating import Templating
from utility.exceptions import (
    StorageStatusCheckFailed,
    AggregateNodeStatusCheckFailed,
)
from utility.utils import (
    install_rpm,
    enable_postgresql_version,
    create_directory,
    set_permissions,
    exec_cmd,
    get_ip_address,
)

log = logging.getLogger(__name__)


class Deployment(object):
    """
    Noobaa SA deployment
    """

    def __init__(self):
        """
        Initializes the necessary variables needed for
        Noobaa Standalone Deployment
        """
        self.rpm_url = config.ENV_DATA["noobaa_sa"]
        self.postgres_repo = config.ENV_DATA["postgres_repo"]
        self.packages = config.ENV_DATA["db_packages"]
        self.postgresql_version = config.ENV_DATA["postgresql_version"]
        self.package = config.ENV_DATA["package_json"]
        self.npm = NPM(self.package)
        config.ENV_DATA["ip_address"] = get_ip_address()
        self.sleep = 10

    def install_noobaa_sa(self):
        """
        Installs Noobaa Standalone deployment
        """
        log.info("Installing Noobaa Standalone")
        # install noobaa standalone rpm
        rpm_path = self.download_rpms(rpm_url=self.rpm_url)
        install_rpm(rpm_path=rpm_path)

        # enable postgres repo
        install_rpm(rpm_path=self.postgres_repo)

        # enable postgresql version to default
        enable_postgresql_version(self.postgresql_version)

        # install postgresql
        install_rpm(packages=self.packages)

        # set permissions
        noobaa_core_dir = config.ENV_DATA["noobaa_core_dir"]
        set_permissions(
            directory_path=noobaa_core_dir,
            permissions=777,
            use_sudo=True
        )

        # create storage directory
        previous_dir = os.getcwd()
        storage_dir = config.ENV_DATA["storage_dir"]
        noobaa_core_dir = config.ENV_DATA["noobaa_core_dir"]
        os.chdir(noobaa_core_dir)
        create_directory(name=storage_dir)

        # set permissions to postgresql
        postgresql_dir = config.ENV_DATA["postgresql_dir"]
        set_permissions(
            directory_path=postgresql_dir,
            permissions=777,
            use_sudo=True
        )

        # initialize database directory
        self.initialize_db()

        # run database
        self.run_db()

        # creates DB
        self.create_db()

        # create .env file
        self.generate_env_file()

        # create config-local.js
        self.generate_config_local()

        # run web service
        self.run_web_service()

        # run bg service
        self.run_bg_service()

        # run hosted agents
        self.run_hosted_agents()

        # run s3 endpoint
        self.run_s3_service()

        # create backingstore drives
        backing_stores = config.DEPLOYMENT["backing_stores"]
        backing_store_drive_port = (
            config.DEPLOYMENT["backing_store_drive_port"]
        )
        for num in range(backing_stores):
            backing_store_path = config.DEPLOYMENT["backing_store_drive_path"]
            backing_store_drive = os.path.join(
                backing_store_path,
                f'{config.DEPLOYMENT["backing_store_drive_prefix"]}{num}',
            )
            create_directory(name=backing_store_drive)

            # run backingstore
            backing_store_drive_port += 1
            self.run_backingstore(
                backingstore_path=backing_store_drive,
                port=backing_store_drive_port
            )
            time.sleep(self.sleep)

        # check storage status
        self.check_storage_status()

        # check node status
        self.check_node_status()

        # switch to original directory
        os.chdir(previous_dir)

    def download_rpms(self, rpm_url):
        """
        Downloads RPM

        Args:
            rpm_url (str): RPM URL to download

        Returns:
            str: Path to RPM file

        Raise:
            requests.RequestException: In case rpm failed to download

        """
        # Path to save the RPM package
        rpm_name = rpm_url.split("/")[-1][:-4]
        rpm_file = tempfile.NamedTemporaryFile(
            mode="w+", prefix=f"{rpm_name}_", suffix=".rpm", delete=False
        )
        rpm_file_name = rpm_file.name

        try:
            # Send an HTTP GET request to download the RPM package
            response = requests.get(rpm_url)
            response.raise_for_status()

            # Open a local file and write the RPM content to it
            with open(rpm_file_name, "wb") as f:
                f.write(response.content)
            log.info(f"Downloaded RPM package to {rpm_file_name}")
            return rpm_file_name

        except requests.exceptions.RequestException as ex:
            raise requests.RequestException(
                f"Failed to download RPM package. Exception: {ex}"
            )

    def initialize_db(self):
        """
        Initialize DB
        """
        log.info("Initializing DB")
        self.npm.run_script(cmd="db:init")

    def run_db(self):
        """
        Runs the database
        """
        log.info("starting the DB")
        self.npm.run_script("db", wait=False)
        time.sleep(self.sleep)

    def create_db(self):
        """
        Creates DB
        """
        log.info("Creating DB, users and permissions")
        self.npm.run_script(cmd="db:create")
        time.sleep(self.sleep)

    def run_web_service(self):
        """
        Runs the web service
        """
        log.info("starting the web service")
        self.npm.run_script("web", wait=False)
        time.sleep(self.sleep)

    def run_bg_service(self):
        """
        Runs the bg service
        """
        log.info("starting the bg service")
        self.npm.run_script("bg", wait=False)
        time.sleep(self.sleep)

    def run_s3_service(self):
        """
        Runs the bg service
        """
        log.info("starting the s3 endpoint service")
        self.npm.run_script("s3", wait=False)
        time.sleep(self.sleep)

    def run_hosted_agents(self):
        """
        Runs hosted agent service
        """
        log.info("starting the hosted agent service")
        self.npm.run_script("hosted_agents", wait=False)
        time.sleep(self.sleep)

    def run_backingstore(self, backingstore_path, port):
        """
        Runs the backingstore

        Args:
            backingstore_path (str): path to backingstore drive
            port (int): Port number to start the backingstore drive

        """
        log.info(f"running backing store '{backingstore_path}' at port {port}")
        args = "--", f"{backingstore_path}", "--port", f"{port}"
        script_name = "backingstore"
        self.npm.run_script(cmd=script_name, args=args, wait=False)

    def check_storage_status(self):
        """
        Checks Storage status

        Raises:
            StorageCheckFailed: In case storage check failed

        """
        log.info("checking storage status")
        script_name = "api"
        args = "--", "node", "sync_monitor_to_store"
        op = self.npm.run_script(cmd=script_name, args=args)
        if op != 0:
            raise StorageStatusCheckFailed
        else:
            log.info("Storage Check successfully passed")

    def check_node_status(self):
        """
        Checks aggregate node status

        Raises:
            StorageCheckFailed: In case storage check failed

        """
        log.info("checking aggregate node status")
        script_name = "api"
        args = "--", "node", "aggregate_nodes", "{}"
        op = self.npm.run_script(cmd=script_name, args=args)
        if op != 0:
            raise AggregateNodeStatusCheckFailed
        else:
            log.info("Aggregate node status check successfully passed")

    def generate_env_file(self):
        """
        Creates .env file
        """
        log.info("creating .env file")
        templating = Templating()
        env_template = "env.j2"
        env_str = templating.render_template(env_template, config.ENV_DATA)
        env_file = config.ENV_DATA["env_file"]
        cmd = f"touch {env_file}"
        exec_cmd(cmd=cmd, use_sudo=True)
        cmd_permissions = f"chmod 666 {env_file}"
        exec_cmd(cmd=cmd_permissions, use_sudo=True)
        with open(env_file, "w") as f:
            f.write(env_str)

    def generate_config_local(self):
        """
        Creates config-local
        """
        log.info("creating config-local.js file")
        config_local = os.path.join(
            config.ENV_DATA["template_dir"], "config-local.js"
        )
        cmd = f'cp {config_local} {config.ENV_DATA["config_local"]}'
        exec_cmd(cmd=cmd, use_sudo=True)
