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


class HealthStatusFailed(Exception):
    pass


class BucketUpdateFailed(Exception):
    pass


class MissingFileOrDirectory(Exception):
    pass


class NoSuchBucket(Exception):
    pass


class BucketNotEmpty(Exception):
    pass


class BucketAlreadyExists(Exception):
    pass


class AccessDenied(Exception):
    pass


class UnexpectedBehaviour(Exception):
    pass


class NoSuchKey(Exception):
    pass
