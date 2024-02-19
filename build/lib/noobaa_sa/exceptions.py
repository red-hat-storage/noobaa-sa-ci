class AccountCreationFailed(Exception):
    pass


class AccountListFailed(Exception):
    pass


class AccountDeletionFailed(Exception):
    pass


class InvalidDeploymentType(Exception):
    pass


class AccountStatusFailed(Exception):
    pass


class BucketCreationFailed(Exception):
    pass


class BucketListFailed(Exception):
    pass


class BucketDeletionFailed(Exception):
    pass


class BucketStatusFailed(Exception):
    pass


class BucketUpdateFailed(Exception):
    pass


class MissingFileOrDirectoryException(Exception):
    pass
