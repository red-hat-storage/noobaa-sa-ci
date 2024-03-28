import logging
import os

import pytest
from common_ci_utils.file_system_utils import compare_md5sums
from common_ci_utils.random_utils import (
    generate_random_hex,
    generate_unique_resource_name,
)

from noobaa_sa.exceptions import NoSuchBucket, NoSuchKey

log = logging.getLogger(__name__)


class TestS3ObjectOperations:
    """
    Test S3 object operations using NSFS
    """

    def test_put_and_get_obj(self, c_scope_s3client):
        """
        Test S3 PutObject and GetObject operations:
        1. Put an object to a bucket
        2. Get the object from the bucket
        3. Compare the retrieved object content to the original

        """
        bucket = c_scope_s3client.create_bucket()

        # 1. Put an object to a bucket
        put_obj_contents = generate_random_hex(500)
        response = c_scope_s3client.put_object(
            bucket, "random_str.txt", body=put_obj_contents
        )
        code = response["Code"]
        assert code == 200, f"put_object failed with response code {code}"

        # 2. Get the object from the bucket
        response = c_scope_s3client.get_object(bucket, "random_str.txt")
        code = response["Code"]
        assert code == 200, f"get_object failed with response code {code}"

        # 3. Compare the retrieved object content to the original
        get_obj_contents = response["Body"].read().decode("utf-8")
        assert (
            put_obj_contents == get_obj_contents
        ), "Retrieved object content does not match"

    def test_object_deletion(self, c_scope_s3client):
        """
        Test the S3 DeleteObject and DeleteObjects operations:
        1. Put objects to a bucket
        2. Delete one of the objects via DeleteObject
        3. Verify the deleted object is no longer listed
        4. Delete some of the remaining objects via DeleteObjects
        5. Verify the deleted objects are no longer listed
        6. Verify the non deleted objects are still listed

        """
        bucket = c_scope_s3client.create_bucket()

        # 1. Put objects to a bucket
        written_objects = c_scope_s3client.put_random_objects(bucket, amount=10)

        # 2. Delete one of the objects via DeleteObject
        response = c_scope_s3client.delete_object(bucket, written_objects[0])
        assert (
            response["Code"] == 204
        ), f"delete_object resulted in an unexpected response: {response}"

        # 3. Verify the deleted object is no longer listed
        post_deletion_objects = c_scope_s3client.list_objects(bucket)
        assert (
            written_objects[0] not in post_deletion_objects
        ), "Deleted object was still listed after deletion via delete_object"

        # 4. Delete some of the remaining objects via DeleteObjects
        response = c_scope_s3client.delete_objects(bucket, written_objects[1:5])
        assert (
            response["Code"] == 200
        ), f"delete_objects resulted in an unexpected response: {response}"

        # 5. Verify the deleted objects are no longer listed
        post_deletion_objects = c_scope_s3client.list_objects(bucket)
        assert all(
            obj not in post_deletion_objects for obj in written_objects[1:5]
        ), "Deleted objects were still listed post deletion via delete_objects"

        # 6. Verify the non deleted objects are still listed
        assert (
            written_objects[5:] == post_deletion_objects
        ), "Non deleted objects were not listed post deletion"

    def test_copy_object(self, c_scope_s3client):
        """
        Test the S3 CopyObject operation:
        1. Put an object to a bucket
        2. Copy the object to the same bucket under a different key
        3. Verify the copied object content matches the original
        4. Copy the object to a different bucket
        5. Verify the copied object content matches the original

        """
        bucket_a = c_scope_s3client.create_bucket()
        bucket_b = c_scope_s3client.create_bucket()

        # 1. Put an object to a bucket
        obj_name = generate_unique_resource_name(prefix="obj")
        obj_data_body = generate_random_hex(500)
        c_scope_s3client.put_object(bucket_a, obj_name, body=obj_data_body)

        # 2. Copy the object to the same bucket under a different key
        c_scope_s3client.copy_object(
            src_bucket=bucket_a,
            src_key=obj_name,
            dest_bucket=bucket_a,
            dest_key=obj_name,
        )

        # 3. Verify the copied object content matches the original
        copied_obj_data = (
            c_scope_s3client.get_object(bucket_a, obj_name)["Body"]
            .read()
            .decode("utf-8")
        )
        assert obj_data_body == copied_obj_data, "Copied object content does not match"

        # 4. Copy the object to a different bucket
        c_scope_s3client.copy_object(
            src_bucket=bucket_a,
            src_key=obj_name,
            dest_bucket=bucket_b,
            dest_key=obj_name,
        )

        # 5. Verify the copied object content matches the original
        copied_obj_data = (
            c_scope_s3client.get_object(bucket_b, obj_name)["Body"]
            .read()
            .decode("utf-8")
        )
        assert obj_data_body == copied_obj_data, "Copied object content does not match"

    def test_data_integrity(self, c_scope_s3client, tmp_directories_factory):
        """
        Test data integrity of objects written and read via S3:
        1. Put random objects to a bucket
        2. Download the bucket contents
        3. Compare the MD5 sums of the original and downloaded objects

        """
        origin_dir, results_dir = tmp_directories_factory(
            dirs_to_create=["origin", "result"]
        )
        bucket = c_scope_s3client.create_bucket()

        # 1. Put random objects to a bucket
        original_objs_names = c_scope_s3client.put_random_objects(
            bucket, amount=10, min_size="1M", max_size="2M", files_dir=origin_dir
        )

        # 2. Download the bucket contents
        c_scope_s3client.download_bucket_contents(bucket, results_dir)
        downloaded_objs_names = os.listdir(results_dir)

        # 3. Compare the MD5 sums of the original and downloaded objects
        # Verify that the number of original and downloaded objects match
        assert len(original_objs_names) == len(
            downloaded_objs_names
        ), "Downloaded and original objects count does not match"

        # Sort the two lists to align for the comparison via zip
        original_objs_names.sort()
        downloaded_objs_names.sort()

        # Compare the MD5 sums of each origina object against its downloaded counterpart
        for original, downloaded in zip(original_objs_names, downloaded_objs_names):
            original_full_path = os.path.join(origin_dir, original)
            downloaded_full_path = os.path.join(results_dir, downloaded)
            md5sums_match = compare_md5sums(original_full_path, downloaded_full_path)
            assert md5sums_match, f"MD5 sums do not match for {original}"

    def test_expected_put_and_get_failures(self, c_scope_s3client):
        """
        Test S3 PutObject and GetObject operations that are expected to fail:
        1. Attempt putting an object to a non existing bucket
        2. Attempt getting a non existing object

        """
        bucket = c_scope_s3client.create_bucket()

        # 1. Attempt putting an object to a non existing bucket
        response = c_scope_s3client.put_object(
            bucket_name="non-existant-bucket", object_key="obj", body="body"
        )
        assert response["Code"] == "NoSuchBucket", (
            "Attempting to put an object on a non existing bucket did not fail as expected",
            response,
        )

        # 2. Attempt getting a non existing object
        response = c_scope_s3client.get_object(bucket, "non_existing_obj")
        assert response["Code"] == "NoSuchKey", (
            "Attempting to get a non existing object did not fail as expected",
            response,
        )

    def test_expected_copy_failures(self, c_scope_s3client):
        """
        Test S3 CopyObject operations that are expected to fail:
        1. Attempt copying from a non existing bucket
        2. Attempt copying an object to a non existing bucket
        3. Attempt copying a non existing object

        """
        bucket = c_scope_s3client.create_bucket()
        obj_key = generate_unique_resource_name(prefix="obj")
        c_scope_s3client.put_object(bucket, obj_key, body="body")

        # 1. Attempt copying FROM a non existing bucket
        response = c_scope_s3client.copy_object(
            src_bucket="non_existing_bucket",
            src_key="non_existing_obj",
            dest_bucket=bucket,
            dest_key="dest_key",
        )
        assert response["Code"] == "NoSuchBucket", (
            "Attempting to copy from a non existing bucket did not fail as expected",
            response,
        )

        # 2. Attempt copying an object TO a non existing bucket
        response = c_scope_s3client.copy_object(
            src_bucket=bucket,
            src_key=obj_key,
            dest_bucket="non_existing_bucket",
            dest_key="dest_key",
        )
        assert response["Code"] == "NoSuchBucket", (
            "Attempting to copy to a non existing bucket did not fail as expected",
            response,
        )

        # 3. Attempt copying a non existing object
        response = c_scope_s3client.copy_object(
            src_bucket=bucket,
            src_key="non_existing_obj",
            dest_bucket=bucket,
            dest_key="dest_key",
        )
        assert response["Code"] == "NoSuchKey", (
            "Attempting to copy a non existing object did not fail as expected",
            response,
        )
