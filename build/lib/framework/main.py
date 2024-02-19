import argparse
import framework
import os
import pytest
import sys
import yaml


# Directories
TOP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE_DIR = os.path.join(TOP_DIR, "templates")


def process_arguments(arguments):
    """
    This function process the arguments which are passed to noobaa-sa-ci

    Args:
        arguments (list): List of arguments

    """
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--conf", action="append", default=[])

    args, unknown = parser.parse_known_args(args=arguments)
    load_config(args.conf)


def load_config(config_files):
    """
    This function load the config files in the order defined in config_files
    list.

    Args:
        config_files (list): config file paths

    """
    for config_file in config_files:
        with open(os.path.abspath(os.path.expanduser(config_file))) as file_stream:
            custom_config_data = yaml.safe_load(file_stream)
            framework.config.update(custom_config_data)


def main(argv=None):
    """
    Main function
    """
    arguments = argv or sys.argv[1:]
    arguments.extend(
        [
            "-p",
            "framework.ssh_connection_manager",
            "-p",
            "framework.customizations.custom_cmd_line_arguments",
        ]
    )
    process_arguments(arguments)
    framework.config.ENV_DATA["template_dir"] = TEMPLATE_DIR
    return pytest.main(arguments)
