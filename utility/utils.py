"""
General utility functions
"""

import logging
import os
import random
import string
import re

from framework import config
from framework.ssh_connection_manager import SSHConnectionManager
from common_ci_utils.file_system_utils import compare_md5sums
from common_ci_utils.random_utils import parse_size_to_bytes

from utility.retry import logger

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


def get_env_config_root_full_path():
    """
    Get the full path of directory that's specified as the config_root
    in under ENV_DATA in the CI's configuration

    Returns:
        str: The full path of the configuration root directory on the remote
        machine

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
    for uploaded, downloaded in zip(uploaded_objs_names, downloaded_objs_names):
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
            if file_chunk == b"":
                break
            all_chunks.append(file_chunk)
    return all_chunks


def generate_random_key(length=20, alphanumeric=True):
    """
    Generates a random string with the given length

    args:
        length (int): The length of the string - must be at least 2

    returns:
        str: A random string.
    """
    # Generate mandatory characters
    mandatory_chars = []
    mandatory_chars.append(random.choice(string.ascii_uppercase))
    mandatory_chars.append(random.choice(string.digits))

    valid_special_characters = ""
    if not alphanumeric:
        # Generate the rest of the key and make sure it doesn't contain any invalid characters
        invalid_chars = ["\\", "/", " ", '"', "'"]
        valid_special_characters = "".join(
            ch for ch in string.punctuation if ch not in invalid_chars
        )

    valid_characters = string.ascii_letters + string.digits + valid_special_characters
    key_chars = random.choices(valid_characters, k=length - len(mandatory_chars))

    # Add the mandatory characters to random positions in the key
    for ch in mandatory_chars:
        key_chars.insert(random.randint(0, len(key_chars)), ch)

    return "".join(key_chars)


def camel_to_snake(s):
    """
    Convert a CamelCase string to a snake_case string.

    Args:
        s (str): The CamelCase string to convert

    Returns:
        str: The snake_case string
    """
    snake_case = []
    for i, ch in enumerate(s):
        # Add an underscore before an uppercase letter, except the first one
        if ch.isupper() and i != 0:
            snake_case.append("_")
        snake_case.append(ch.lower())
    return "".join(snake_case)


def is_uid_gid_available(uid, gid):
    """
    Check if the UID and GID are available.

    Args:
        uid (int): The UID to check
        gid (int): The GID to check

    Returns:
        bool: True if the UID and GID are available, False otherwise

    """
    conn = SSHConnectionManager().connection
    check_uid_cmd = f"getent passwd {uid}"
    check_gid_cmd = f"getent group {gid}"
    uid_retcode, _, _ = conn.exec_cmd(check_uid_cmd)
    gid_retcode, _, _ = conn.exec_cmd(check_gid_cmd)
    return uid_retcode != 0 and gid_retcode != 0


def is_linux_username_available(username):
    """
    Check if the username is available.

    Args:
        username (str): The username to check

    Returns:
        bool: True if the username is available, False otherwise

    """
    conn = SSHConnectionManager().connection
    check_user_cmd = f"getent passwd {username}"
    user_retcode, _, _ = conn.exec_cmd(check_user_cmd)
    return user_retcode != 0


def flatten_dict(d):
    """
    Flatten a nested dictionary into a single-level dictionary that contains
    only the leaves-level key-value pairs.

    Args:
        d (dict): The nested dictionary to flatten.

    Returns:
        dict: The flattened dictionary.

    Example:
        >>> d = {
        ...     "a": 1,
        ...     "b": {
        ...         "c": 2,
        ...         "d": [
        ...             {"e": 3}
        ...         ]
        ...     }
        ... }
        >>> flatten_dict(d)
        {'a': 1, 'c': 2, 'e': 3}
    """

    def _recur_flatten_dict(d):
        items = []
        for k, v in d.items():
            if isinstance(v, dict):
                # If the value is a dict, recursively flatten it and extend the items list
                items.extend(_recur_flatten_dict(v).items())
            elif isinstance(v, list):
                # If the value is a list, iterate through the list
                for item in v:
                    if isinstance(item, dict):
                        # If the list item is a dictionary, recursively flatten it and extend the items list
                        items.extend(_recur_flatten_dict(item).items())
            else:
                # If the value is neither a dictionary nor a list, add the key-value pair to the items list
                items.append((k, v))
        return dict(items)

    return _recur_flatten_dict(d)


def get_noobaa_sa_rpm_name():
    """
    Get the name of the RPM that was used to
    install NooBaa on the remote machine

    Returns:
        str: The NooBaa SA RPM name
        I.E noobaa-core-5.17.0-20241026.el9.x86_64

    """
    try:
        conn = SSHConnectionManager().connection
        cmd = "rpm -qa | grep noobaa"
        _, stdout, _ = conn.exec_cmd(cmd)
        return stdout.strip()
    except Exception as e:
        log.error(e)
        return ""


def get_noobaa_sa_version_string(rpm_name):
    """
    Extract the X.Y.Z version from the given NooBaa SA RPM name.

    Args:
        rpm_name (str): The NooBaa SA RPM name (e.g., "noobaa-core-5.17.0-20241026.el9.x86_64")

    Returns:
        str: The version in X.Y.Z format (e.g., "5.17.0"),
             or an empty string if the format is invalid.
    """
    try:
        # Regex to extract X.Y.Z from the RPM name
        match = re.search(r"noobaa-core-(\d+)\.(\d+)\.(\d+)", rpm_name)
        if match:
            return ".".join(match.groups())  # Join X, Y, Z as a string
        else:
            log.error("No version found in RPM name")
            return ""
    except Exception as e:
        log.error(e)
        return ""


def list_all_versions_of_the_object(s3client_obj, bucket_name, object_name):
    """
    returns list of version ids of the specific object

    Args:
        s3client_obj (obj): S3 client object
        bucket_name  (str): versioned Bucket name
        object_name  (str): Object name
    Returns: list
    """
    version_id_list = []
    log.info(f"Listing all versions available for object {object_name}")
    response = s3client_obj.list_object_versions(bucket_name)
    log.info(response)
    for v in response["Versions"]:
        if v["Key"] == object_name:
            version_id_list.append(v["VersionId"])
    return version_id_list
