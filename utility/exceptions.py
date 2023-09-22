"""
This module contains user defined exceptions
"""


class RPMInstallationFailed(Exception):

    pass


class PermissionsFailedToChange(Exception):
    pass


class StorageStatusCheckFailed(Exception):
    pass


class AggregateNodeStatusCheckFailed(Exception):
    pass
