import os
import logging
import tempfile
import boto3
from boto3.s3.transfer import TransferConfig
from noobaa_sa.exceptions import BucketCreationFailed
from utility.utils import generate_unique_resource_name, generate_random_files
from botocore.exceptions import ClientError

log = logging.getLogger(__name__)


# TODO: Add robust exception handling to all the methods
class S3Client:
    """
    A wrapper class for S3 operations using boto3

    The 'access_key' and 'secret_key' are set as read-only properties.
    This allows to keep track of the buckets created by the specific account and
    to delete only them if needed.

    To use different credentials, instantiate a new S3Client object.

    """

    static_tls_crt_path = ""

    def __init__(self, endpoint, access_key, secret_key, verify_tls=True):
        self.endpoint = endpoint
        self._access_key = access_key
        self._secret_key = secret_key
        self.verify_tls = verify_tls

        # Set the AWS_CA_BUNDLE environment variable in order to
        # include the TLS certificate in the boto3 and AWS CLI calls
        if self.verify_tls:
            os.environ["AWS_CA_BUNDLE"] = S3Client.static_tls_crt_path

        self._boto3_resource = boto3.resource(
            "s3",
            endpoint_url=self.endpoint,
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
        )
        self._boto3_client = self._boto3_resource.meta.client

    @property
    def access_key(self):
        return self._access_key

    @property
    def secret_key(self):
        return self._secret_key

    def create_bucket(self, bucket_name=""):
        """
        Create a bucket in an S3 account using boto3

        Args:
            bucket_name (str): The name of the bucket to create.
                               If not specified, a random name will be generated.

        Returns:
            str: The name of the created bucket

        """
        if bucket_name == "":
            bucket_name = generate_unique_resource_name(prefix="bucket")
        log.info(f"Creating bucket {bucket_name} via boto3")
        response = self._boto3_client.create_bucket(Bucket=bucket_name)
        if "Location" not in response:
            raise BucketCreationFailed(
                f"Could not create bucket {bucket_name}. Response: {response}"
            )
        log.info(f"Bucket {bucket_name} created successfully")
        return bucket_name

    def delete_bucket(self, bucket_name, empty_before_deletion=False):
        """
        Delete a bucket in an S3 account using boto3
        If the bucket is not empty, it will not be deleted unless empty_bucket is set to True

        Args:
            bucket_name (str): The name of the bucket to delete
            empty_before_deletion (bool): Whether to empty the bucket before attempting deletion

        """
        if empty_before_deletion:
            self.delete_all_objects_in_bucket(bucket_name)

        log.info(f"Deleting bucket {bucket_name} via boto3")
        try:
            self._boto3_client.delete_bucket(Bucket=bucket_name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "BucketNotEmpty":
                log.error(
                    f"Bucket {bucket_name} is not empty and will not be deleted. "
                    f"Set empty_before_deletion to True to delete it anyway."
                )
                raise e
            elif e.response["Error"]["Code"] == "NoSuchBucket":
                log.warn(f"Bucket {bucket_name} does not exist and cannot be deleted")
            else:
                log.error(f"Failed to delete bucket {bucket_name}: {e}")
                raise e
        else:
            log.info(f"Bucket {bucket_name} deleted successfully")

    def list_buckets(self):
        """
        List buckets in an S3 account using boto3

        Returns:
            list: A list of the names of the buckets

        """
        log.info("Listing buckets via boto3")
        response = self._boto3_client.list_buckets()
        listed_buckets = [bucket_data["Name"] for bucket_data in response["Buckets"]]
        log.info(f"Listed buckets: {listed_buckets}")
        return listed_buckets

    def list_objects(self, bucket_name, prefix="", use_v2=False):
        """
        List objects in an S3 bucket using boto3

        Args:
            bucket_name (str): The name of the bucket
            prefix (str): A prefix where the objects will be listed from
            use_v2 (bool): Whether to use list_objects_v2 instead of list_objects

        Returns:
            list: A list of the names of the objects

        """
        log.info(f"Listing objects in bucket {bucket_name} via boto3")
        list_objects_method = (
            self._boto3_client.list_objects_v2
            if use_v2
            else self._boto3_client.list_objects
        )
        output = list_objects_method(Bucket=bucket_name, Prefix=prefix)
        listed_objects = []
        if "Contents" in output:
            listed_objects = [obj["Key"] for obj in output["Contents"]]
        log.info(f"Listed objects: {listed_objects}")
        return listed_objects

    def put_object(self, bucket_name, object_key, object_data):
        """
        Put an object in an S3 bucket using boto3

        """
        log.info(f"Putting object {object_key} in bucket {bucket_name} via boto3")
        self._boto3_client.put_object(
            Bucket=bucket_name, Key=object_key, Body=object_data
        )

    def get_text_object_str(self, bucket_name, object_key):
        """
        Get the contents of a text object in an S3 bucket using boto3

        For other types of objects, use get_object_contents

        Returns:
            str: The contents of the object

        """
        return self.get_object(bucket_name, object_key).read().decode("utf-8")

    def get_object(self, bucket_name, object_key):
        """
        Get the contents of an object in an S3 bucket using boto3

        Args:
            bucket_name (str): The name of the bucket
            object_key (str): The key of the object

        Returns:
            A botocore.response.StreamingBody object that can be read from

        """
        log.info(f"Getting object {object_key} from bucket {bucket_name} via boto3")
        output = self._boto3_client.get_object(Bucket=bucket_name, Key=object_key)
        return output["Body"]

    def upload_directory(self, local_dir, bucket_name, prefix=""):
        """
        Upload a directory to an S3 bucket using boto3

        Args:
            local_dir (str): The local directory to upload
            bucket_name (str): The name of the bucket to upload to
            prefix (str): A prefix where the directory will be written in the bucket

        """
        log.info(
            f"Uploading directory {local_dir} to s3://{bucket_name}/{prefix} via boto3"
        )
        transfer_config = TransferConfig(use_threads=True)
        for root, _, files in os.walk(local_dir):
            for filename in files:
                local_path = os.path.join(root, filename)
                relative_path = os.path.relpath(local_path, local_dir)
                s3_path = os.path.join(prefix, relative_path)

                print(f"Uploading {local_path} to {bucket_name}/{s3_path}")
                self._boto3_client.upload_file(
                    local_path, bucket_name, s3_path, Config=transfer_config
                )

    def download_bucket_contents(self, bucket_name, local_dir, prefix=""):
        """
        Downloads the contents of an S3 bucket prefix to a local directory.
        If the prefix is empty, the entire bucket will be downloaded.

        Args:
            bucket (str): The name of the S3 bucket.
            local_dir (str): The local directory to download the contents into.
            prefix (str): The S3 prefix to download from (acts like a directory).
        """

        transfer_config = TransferConfig(use_threads=True)

        log.info(f"Downloading s3:///{bucket_name}/{prefix} to {local_dir} via boto3")
        # List objects within the specified prefix
        for obj in self.list_objects(bucket_name, prefix, use_v2=True):
            # Construct the full local path
            relative_path = os.path.relpath(obj, prefix)
            local_file_path = os.path.join(local_dir, relative_path)

            # Ensure local directory structure mirrors S3
            local_file_dir = os.path.dirname(local_file_path)
            if not os.path.exists(local_file_dir):
                os.makedirs(local_file_dir)

            print(f"Downloading {obj} to {local_file_path}")
            self._boto3_client.download_file(
                bucket_name, obj, local_file_path, Config=transfer_config
            )

    def delete_object(self, bucket_name, object_key):
        """
        Delete an object from an S3 bucket using boto3

        """
        log.info(f"Deleting object {object_key} from bucket {bucket_name} via boto3")
        self._boto3_client.delete_object(Bucket=bucket_name, Key=object_key)

    def put_random_objects(
        self, bucket_name, amount=1, obj_size="1M", prefix="", files_dir=""
    ):
        """
        Write random objects to an S3 bucket

        Args:
            bucket_name (str): The name of the bucket to write to
            amount (int): The number of objects to write
            obj_size (str): The size of each object, specified in a format understood by the 'dd' command.
                            The size format is '[number][unit]', where 'unit' can be 'K', 'M', or 'G'.
            prefix (str): A prefix where the objects will be written in the bucket
            files_dir (str): A directory where the objects will be written locally.
                             If not specified, a temporary directory will be used.

        Returns:
            list: A list of the names of the objects written to the bucket

        """
        written_objs = []

        # Determine the directory to use for file storage
        actual_files_dir = files_dir if files_dir else tempfile.mkdtemp()

        # Generate random files in the specified directory
        written_objs += generate_random_files(actual_files_dir, amount, obj_size)

        # Ensure the prefix ends with a slash if it is not empty
        if prefix and not prefix.endswith("/"):
            prefix += "/"

        self.upload_directory(actual_files_dir, bucket_name, prefix)

        return written_objs

    def delete_all_objects_in_bucket(self, bucket_name):
        """
        Deletes all objects in the specified S3 bucket.

        Args:
            bucket_name (str): The name of the S3 bucket.
        """
        # TODO: Support buckets with versioning enabled
        log.info(f"Deleting all objects in bucket {bucket_name} via boto3")
        self._boto3_resource.Bucket(bucket_name).objects.all().delete()
