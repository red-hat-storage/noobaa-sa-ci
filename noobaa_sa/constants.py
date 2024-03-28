"""
This module contains constant value which will be used across project
"""

DEPLOYMENT_TYPES = ["nsfs", "db"]
NSFS_DEPLOYMENT = "nsfs"
DB_DEPLOYMENT = "db"
NSFS_SERVICE_NAME = "noobaa_nsfs"
DEFAULT_FS_BACKEND = "GPFS"
UNWANTED_LOG = "2>/dev/null"
DEFAULT_NSFS_PORT = 6443
DEFAULT_CONFIG_ROOT_PATH = "/etc/noobaa.conf.d"
EXPECTED_ACCESS_KEY_LEN = 20
EXPECTED_SECRET_KEY_LEN = 40
