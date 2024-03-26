"""
General utility functions
"""

import logging
import os
import random

from framework import config
from framework.ssh_connection_manager import SSHConnectionManager
from common_ci_utils.file_system_utils import compare_md5sums
from common_ci_utils.random_utils import parse_size_to_bytes


log = logging.getLogger(__name__)


def get_noobaa_sa_host_home_path():
    """
    Get the full path of the home directory on the remote machine

    Returns:
        str: The full path of the home directory on the remote machine

    """
    cmd = "echo $HOME"
    _, stdout, _ = SSHConnectionManager().connection.exec_cmd(cmd)
    return stdout


def get_current_test_name():
    """
    Get the name of the current test

    Returns:
        str: The name of the current PyTest test

    """
    return os.environ.get("PYTEST_CURRENT_TEST").split(":")[-1].split(" ")[0]


def get_config_root_full_path():
    """
    Get the full path of the configuration root directory on the remote machine

    Returns:
        str: The full path of the configuration root directory on the remote machine

    """
    config_root = config.ENV_DATA["config_root"]

    if config_root.startswith("~/") == False:
        return config_root

    config_root = config_root.split("~/")[1]
    return f"{get_noobaa_sa_host_home_path()}/{config_root}"


def check_data_integrity(origin_dir, results_dir):
    """
    Ckeck the data integrity of downloaded objects with uploaded objects

    Args:
        origin_dir (str): Source directory location of files
        results_dir (str): Destination directory location of files
    Returns:
        bool: Boolean value based on comparision

    """

    uploaded_objs_names = os.listdir(origin_dir)
    downloaded_objs_names = os.listdir(results_dir)
    if not len(uploaded_objs_names) == len(downloaded_objs_names):
        log.error("Downloaded and original objects count does not match")
        return False
    uploaded_objs_names.sort()
    downloaded_objs_names.sort()
    for uploaded, downloaded in zip(
        uploaded_objs_names, downloaded_objs_names
    ):
        original_full_path = os.path.join(origin_dir, uploaded)
        downloaded_full_path = os.path.join(results_dir, downloaded)
        if not compare_md5sums(original_full_path, downloaded_full_path):
            log.error(f"Mismatch for object {uploaded} and {downloaded}")
            return False
        log.info(f"MD5sums are matched for object {uploaded} and {downloaded}")
    return True


def split_file_data_for_multipart_upload(file_name, part_size=None):
    """
    Split original file into defined or random size

    args:
        file_name (str): Name of the file
        part_size (str): Fixed size of file chunk if part_size is not None
                         Random size of file chunk if part_size is None

    return:
        list : List of file chunks

    """
    if part_size is not None:
        new_part_size = parse_size_to_bytes(part_size)
    else:
        file_size = os.path.getsize(file_name)
        new_part_size = random.randint(1, file_size)
    all_chunks = []
    with open(file_name, "rb") as f:
        while True:
            log.info(f"Reading {new_part_size} chunks of the {file_name}")
            file_chunk = f.read(new_part_size)
            if file_chunk == b'':
                break
            all_chunks.append(file_chunk)
    return all_chunks
