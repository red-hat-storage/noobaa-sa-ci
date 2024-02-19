from framework import config
from noobaa_sa.account import DBAccount, NSFSAccount
from noobaa_sa.constants import DB_DEPLOYMENT, DEPLOYMENT_TYPES, NSFS_DEPLOYMENT
from noobaa_sa.exceptions import InvalidDeploymentType


class AccountFactory:
    """
    Account factory/manager to get appropriate account object based on
    deployment type
    """

    def __init__(self):
        self.deployment_type = config.ENV_DATA["deployment_type"]

    def get_account(self, account_json):
        """
        Gets the appropriate account instance based on deployment type

        Args:
            account_json (str): Path to account json file

        Returns:
            instance: Appropriate account instance based on deployment type

        """
        if self.deployment_type == NSFS_DEPLOYMENT:
            return NSFSAccount(account_json)
        elif self.deployment_type == DB_DEPLOYMENT:
            return DBAccount(account_json)
        else:
            raise InvalidDeploymentType(
                f"Invalid deployment type: {self.deployment_type}. Supported deployments are {DEPLOYMENT_TYPES}"
            )
