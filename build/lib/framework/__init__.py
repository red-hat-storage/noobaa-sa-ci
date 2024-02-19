import os

from common_ci_utils.models import Config


THIS_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG_PATH = os.path.join(THIS_DIR, "default_config.yaml")

config = Config(DEFAULT_CONFIG_PATH=DEFAULT_CONFIG_PATH)
