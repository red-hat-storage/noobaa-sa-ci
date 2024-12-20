import logging
import os
import pytest
import random

from common_ci_utils.random_utils import (
    generate_unique_resource_name,
    generate_random_files,
)
from utility.utils import (
    check_data_integrity,
    get_env_config_root_full_path,
    split_file_data_for_multipart_upload,
)
from noobaa_sa import constants
from framework import config
from framework.customizations.marks import tier1
from noobaa_sa.s3_client import S3Client
from utility.bucket_utils import (
    upload_incomplete_multipart_object,
    list_all_versions_of_the_object,
)

log = logging.getLogger(__name__)


class TestMultipartOperations:
    """
    Test S3 object multipart operations on NSFS
    """

    @tier1
    def test_multipart_upload(
        self,
        c_scope_s3client,
        tmp_directories_factory,
    ):
        """
        Test basic s3 operations using a noobaa bucket:
        1. Create an account
        2. Create a bucket using S3
        3. Write multipart objects to the bucket
        4. List multipart objects from the bucket

        """
        log.info("Uploading multipart object")
        # 1. Create a bucket using S3
        bucket_name = c_scope_s3client.create_bucket()
        resp = upload_incomplete_multipart_object(
            bucket_name, c_scope_s3client, tmp_directories_factory
        )
        obj_name = resp["object_names"][0]
        log.info("Trying to complete multipart operation for the object")
        mp_response = c_scope_s3client.complete_multipart_object_upload(
            resp["bucket_name"],
            obj_name,
            resp[f"{obj_name}_upload_id"],
            resp["all_part_info"],
        )
        assert (
            mp_response["ResponseMetadata"]["HTTPStatusCode"] == 200
        ), "Failed to upload multipart object"
        log.info(mp_response)

    @tier1
    def test_multipart_download(self, c_scope_s3client, tmp_directories_factory):
        """
        Test basic s3 operations using a noobaa bucket:
        1. Write multipart objects to the bucket
        2. Download the objects from the bucket and verify data integrity

        """
        # 1. Create a bucket using S3
        bucket_name = c_scope_s3client.create_bucket()
        log.info("Uploading multipart object")
        resp = upload_incomplete_multipart_object(
            bucket_name, c_scope_s3client, tmp_directories_factory
        )
        obj_name = resp["object_names"][0]
        log.info("Completing multipart operation for the object")
        mp_response = c_scope_s3client.complete_multipart_object_upload(
            resp["bucket_name"],
            obj_name,
            resp[f"{obj_name}_upload_id"],
            resp["all_part_info"],
        )
        log.info(mp_response)
        log.info("Trying to download multipart object and validating it")
        c_scope_s3client.download_bucket_contents(
            resp["bucket_name"], resp["results_dir"]
        )
        assert check_data_integrity(resp["origin_dir"], resp["results_dir"])
        log.info("Both uploaded and downloaded data are identical")

    @tier1
    def test_list_multipart_objects(self, c_scope_s3client, tmp_directories_factory):
        """
        Test multipart object list operations using BOTO s3:
        1. Write multipart objects to the bucket
        2. List objects from the bucket and verify it

        """
        # 1. Create a bucket using S3
        bucket_name = c_scope_s3client.create_bucket()
        log.info("Uploading multipart object")
        resp = upload_incomplete_multipart_object(
            bucket_name, c_scope_s3client, tmp_directories_factory
        )
        obj_name = resp["object_names"][0]
        log.info("Completing multipart operation for the object")
        mp_response = c_scope_s3client.complete_multipart_object_upload(
            resp["bucket_name"],
            obj_name,
            resp[f"{obj_name}_upload_id"],
            resp["all_part_info"],
        )
        log.info(mp_response)
        log.info("Multipart operation is completed")
        log.info(f"Listing objects present in {resp['bucket_name']}")
        listed_objs = c_scope_s3client.list_objects(resp["bucket_name"])
        log.info(listed_objs)
        assert set(resp["object_names"]).issubset(
            set(listed_objs)
        ), "All uploaded objects are not present in bucket"
        log.info("Uploaded objects are present in bucket")

    @tier1
    def test_multipart_list_parts(self, c_scope_s3client, tmp_directories_factory):
        """
        Test multipart object list operations using BOTO s3:
        1. Write multipart objects to the bucket
        2. List parts objects from the bucket

        """
        # 1. Create a bucket using S3
        bucket_name = c_scope_s3client.create_bucket()
        log.info("Uploading multipart object")
        resp = upload_incomplete_multipart_object(
            bucket_name, c_scope_s3client, tmp_directories_factory
        )
        obj_name = resp["object_names"][0]
        log.info(f"Listing incomplete multipart uploads for the object {obj_name}")
        part_resp = c_scope_s3client.list_uploaded_parts(
            resp["bucket_name"], obj_name, resp[f"{obj_name}_upload_id"]
        )
        assert (
            len(part_resp["Parts"]) != 0
        ), f"Failed to list parts of {resp['object_names'][0]} object"
        log.info(part_resp)
        log.info(f"Listing incomplete parts for {obj_name} completed successfully")
        log.info("Completing multipart operation for the object")
        mp_response = c_scope_s3client.complete_multipart_object_upload(
            resp["bucket_name"],
            obj_name,
            resp[f"{obj_name}_upload_id"],
            resp["all_part_info"],
        )
        log.info(mp_response)
        log.info("Multipart operation is completed")

    @tier1
    def test_list_multipart_uploads(self, c_scope_s3client, tmp_directories_factory):
        """
        Test multipart object list operations using BOTO s3:
        1. Write multipart objects to the bucket
        2. List all incomplete parts from the bucket

        """
        # 1. Create a bucket using S3
        bucket_name = c_scope_s3client.create_bucket()
        log.info("Uploading multipart object")
        resp = upload_incomplete_multipart_object(
            bucket_name, c_scope_s3client, tmp_directories_factory
        )
        obj_name = resp["object_names"][0]
        log.info(
            f"Listing incomplete multipart uploads for the bucket {resp['bucket_name']}"
        )
        part_resp = c_scope_s3client.list_multipart_upload(resp["bucket_name"])
        assert (
            len(part_resp["Uploads"]) != 0
        ), f"Failed to list parts present in {resp['bucket_name']} object"
        log.info(part_resp)
        log.info(
            "Listing incomplete multipart uploads operation completed successfully"
        )
        log.info("Completing multipart operation for the object")
        mp_response = c_scope_s3client.complete_multipart_object_upload(
            resp["bucket_name"],
            obj_name,
            resp[f"{obj_name}_upload_id"],
            resp["all_part_info"],
        )
        log.info(mp_response)
        log.info("Multipart operation is completed")

    @tier1
    def test_multipart_upload_part_copy(
        self, c_scope_s3client, tmp_directories_factory
    ):
        """
        Test multipart object list operations using BOTO s3:
        1. Write multipart objects to the bucket
        2. Create new bucket
        3. Copy object data from bucket created in step 1 to new bucket

        """
        # 1. Create a bucket using S3
        bucket_name = c_scope_s3client.create_bucket()
        log.info("Uploading multipart object")
        resp = upload_incomplete_multipart_object(
            bucket_name, c_scope_s3client, tmp_directories_factory
        )
        obj_name = resp["object_names"][0]
        c_scope_s3client.complete_multipart_object_upload(
            resp["bucket_name"],
            obj_name,
            resp[f"{obj_name}_upload_id"],
            resp["all_part_info"],
        )
        log.info("Creating another bucket to copy data")
        new_bucket = c_scope_s3client.create_bucket()
        log.info("Generating upload id for the multipart object")
        get_upload_id = c_scope_s3client.initiate_multipart_object_upload(
            new_bucket,
            obj_name,
        )
        log.info("Copying data using upload_part_copy method")
        upload_part_copy = c_scope_s3client.multipart_upload_part_copy(
            new_bucket,
            obj_name,
            resp["bucket_name"] + "/" + obj_name,
            1,
            get_upload_id,
        )
        assert (
            upload_part_copy["ResponseMetadata"]["HTTPStatusCode"] == 200
        ), f"Failed to copy data from {resp['bucket_name']} to {new_bucket}"
        log.info(upload_part_copy)
        log.info("Data copied successfully from source bucket to new bucket")
        log.info("Completing multipart operation for new object")
        all_part_info = []
        all_part_info.append(
            {"PartNumber": 1, "ETag": upload_part_copy["CopyPartResult"]["ETag"]}
        )
        c_scope_s3client.complete_multipart_object_upload(
            new_bucket, obj_name, get_upload_id, all_part_info
        )
        log.info("Multipart operation is completed using upload_part_copy method")

    @tier1
    def test_s3_multipart_abort_upload(self, c_scope_s3client, tmp_directories_factory):
        """
        Test multipart object list operations using BOTO s3:
        1. Write multipart objects to the bucket
        2. Abore multipart upload

        """
        # 1. Create a bucket using S3
        bucket_name = c_scope_s3client.create_bucket()
        log.info("Uploading multipart object")
        resp = upload_incomplete_multipart_object(
            bucket_name, c_scope_s3client, tmp_directories_factory
        )
        log.info("Aborting Multipart operation")
        obj_name = resp["object_names"][0]
        abort_resp = c_scope_s3client.abort_multipart_upload(
            resp["bucket_name"], obj_name, resp[f"{obj_name}" + "_upload_id"]
        )
        log.info(abort_resp)
        assert (
            abort_resp["ResponseMetadata"]["HTTPStatusCode"] == 204
        ), f"Failed to abort upload operation for {obj_name}"
        log.info(abort_resp)
        log.info("Multipart operation Aborted successfully")

    @tier1
    @pytest.mark.parametrize(
        argnames="extra_header",
        argvalues=[
            pytest.param(
                {"MetadataDirective": "REPLACE"},
            ),
            pytest.param(
                {"ContentType": "image/jpeg"},
            ),
        ],
        ids=[
            "MetadataDirective",
            "ContentType",
        ],
    )
    def test_copy_non_nsfs_multipart_object(
        self, c_scope_s3client, tmp_directories_factory, extra_header
    ):
        """
        Test multipart copy object operation from one bucket to another using BOTO s3:
        1. Create new bucket and write multipart objects in it
        2. Create another bucket
        3. Copy multipart objects to the newly created bucket by adding x-headers
        4. Validate data from original directory and new bucket using md5sum check

        """
        # 1. Create a bucket using S3
        bucket_name = c_scope_s3client.create_bucket()
        log.info("Uploading multipart object")
        if "MetadataDirective" in extra_header:
            x_header = {"Metadata": {"Key1": "val1"}}
            resp = upload_incomplete_multipart_object(
                bucket_name, c_scope_s3client, tmp_directories_factory, **x_header
            )
        else:
            resp = upload_incomplete_multipart_object(
                bucket_name, c_scope_s3client, tmp_directories_factory
            )
        obj_name = resp["object_names"][0]
        log.info("Completing multipart operation for the object")
        mp_response = c_scope_s3client.complete_multipart_object_upload(
            resp["bucket_name"],
            obj_name,
            resp[f"{obj_name}_upload_id"],
            resp["all_part_info"],
        )
        log.info(mp_response)
        log.info("Multipart operation is completed")
        # create second bucket
        log.info("Creating new bucket to initiate copy operation")
        bucket_to_copy = c_scope_s3client.create_bucket()
        if "MetadataDirective" in extra_header:
            extra_header["Metadata"] = {"Key2": "val2"}
        cp_response = c_scope_s3client.copy_object(
            resp["bucket_name"], obj_name, bucket_to_copy, obj_name, **extra_header
        )
        assert (
            cp_response["ResponseMetadata"]["HTTPStatusCode"] == 200
        ), "Failed to upload multipart object"
        log.info(cp_response)
        c_scope_s3client.download_bucket_contents(bucket_to_copy, resp["results_dir"])
        assert check_data_integrity(resp["origin_dir"], resp["results_dir"])
        log.info("Both uploaded and copied data are identical")

    @tier1
    @pytest.mark.parametrize(
        argnames="fs_option",
        argvalues=[
            pytest.param(
                {"custom_path": True},
            ),
            pytest.param(
                {"custom_fs_backend": "NFSv4"},
            ),
        ],
        ids=[
            "custom_path",
            "custom_fs_backend",
        ],
    )
    def test_copy_obj_to_another_bucket_with_different_fs_options(
        self,
        account_manager,
        bucket_manager,
        tmp_directories_factory,
        set_nsfs_server_config_root,
        fs_option,
    ):
        """
        Test multipart copy object operation from one bucket to another which has different FS_type using BOTO s3:
        1. Create new bucket and write multipart objects in it
        2. Create another bucket with different FS_type
        3. Copy multipart objects to the newly created bucket
        4. Validate data from original directory and new bucket using md5sum check
        """
        # Create account
        account_name, access_key, secret_key = account_manager.create()
        # Create buckets with different FS path
        first_bucket_name = generate_unique_resource_name(prefix="bucket")
        second_bucket_name = generate_unique_resource_name(prefix="bucket")
        bucket_manager.create(account_name, first_bucket_name)
        bucket_manager.create(account_name, second_bucket_name, **fs_option)
        # Create s3 client to perform s3api operation
        set_nsfs_server_config_root(get_env_config_root_full_path())
        nb_sa_host_address = config.ENV_DATA["noobaa_sa_host"]
        s3_client = S3Client(
            endpoint=f"https://{nb_sa_host_address}:{constants.DEFAULT_NSFS_PORT}",
            access_key=access_key,
            secret_key=secret_key,
        )
        resp_dir = {}
        origin_dir, results_dir = tmp_directories_factory(
            dirs_to_create=["origin", "result"]
        )
        # Write multipart objects to the bucket
        object_names = generate_random_files(
            origin_dir,
            1,
            min_size="20M",
            max_size="30M",
        )
        # Upload multipart object
        log.info("Initiate multipart upload process")
        get_upload_id = s3_client.initiate_multipart_object_upload(
            first_bucket_name,
            object_names[0],
        )
        resp_dir[f"{object_names[0]}_upload_id"] = get_upload_id
        all_part_info = []
        file_name = origin_dir + "/" + object_names[0]
        part_size = "10M"
        log.info(f"Split data into {part_size} size")
        part_data = split_file_data_for_multipart_upload(file_name, part_size)
        log.info("Initiating part uploads for multipart object")
        for pd in range(len(part_data)):
            part_id = pd + 1
            part_info = s3_client.initiate_upload_part(
                first_bucket_name,
                object_names[0],
                part_id,
                get_upload_id,
                part_data[pd],
            )
            all_part_info.append({"PartNumber": part_id, "ETag": part_info["ETag"]})
        resp_dir["all_part_info"] = all_part_info
        log.info("Completing multipart operation for the object")
        mp_response = s3_client.complete_multipart_object_upload(
            first_bucket_name,
            object_names[0],
            resp_dir[f"{object_names[0]}_upload_id"],
            resp_dir["all_part_info"],
        )
        log.info(mp_response)
        log.info("Multipart object uploaded successfully")
        log.info("Initiating object copy operation to new bucket")
        cp_response = s3_client.copy_object(
            first_bucket_name,
            object_names[0],
            second_bucket_name,
            object_names[0],
        )
        assert (
            cp_response["ResponseMetadata"]["HTTPStatusCode"] == 200
        ), "Failed to upload multipart object"
        log.info(cp_response)
        log.info("Download copied object and check data integrity with original object")
        s3_client.download_bucket_contents(second_bucket_name, results_dir)
        assert check_data_integrity(origin_dir, results_dir)
        log.info("Both uploaded and copied data are identical")

    @tier1
    def test_multipart_upload_on_versioned_bucket(
        self,
        c_scope_s3client,
        tmp_directories_factory,
    ):
        """
        Test basic s3 operations using a noobaa bucket:
        1. Create bucket and enable versioning on it
        2. Upload 5 copies of data with same key with different chunk size
        3. List all available versions of uploaded data
        4. Download each copy and compare it with original data
        5. Create new non-versioned bucket and copy object in it
        6. Verify copied data is identical with uploaded data
        """
        # 1. Create a bucket using S3 and enable versioning on it
        bucket_name = c_scope_s3client.create_bucket()
        c_scope_s3client.put_bucket_versioning(bucket_name, status="Enabled")
        log.info(f"Enabled bucket versioning on bucket {bucket_name}")
        log.info("Uploading multipart object")
        origin_dir, results_dir = tmp_directories_factory(
            dirs_to_create=["origin", "result"]
        )
        # 2. Write multipart objects to the bucket
        object_name = generate_random_files(
            origin_dir,
            1,
            min_size="20M",
            max_size="30M",
        )
        # Upload multipart object
        log.info("Initiate multipart upload process")
        for _ in range(5):
            upload_id = c_scope_s3client.initiate_multipart_object_upload(
                bucket_name,
                object_name[0],
            )
            all_part_info = []
            file_name = origin_dir + "/" + object_name[0]
            part_size = str(random.randint(1, 10)) + "M"
            log.info(f"Split data into {part_size} size")
            part_data = split_file_data_for_multipart_upload(file_name, part_size)
            log.info("Initiate part uploads for multipart object")
            for pd in range(len(part_data)):
                part_id = pd + 1
                part_info = c_scope_s3client.initiate_upload_part(
                    bucket_name,
                    object_name[0],
                    part_id,
                    upload_id,
                    part_data[pd],
                )
                all_part_info.append({"PartNumber": part_id, "ETag": part_info["ETag"]})

            log.info("Completing multipart operation for the object")
            mp_response = c_scope_s3client.complete_multipart_object_upload(
                bucket_name,
                object_name[0],
                upload_id,
                all_part_info,
            )
            log.info(mp_response)

        # List all versions of the object
        version_list = list_all_versions_of_the_object(
            c_scope_s3client, bucket_name, object_name[0]
        )
        for v in version_list:
            log.info(v)
        assert (
            len(version_list) == 5
        ), f"Uploaded 5 copies and listed {len(version_list)} copies of data"
        log.info("Uploaded copies and listed copies count is same")
        log.info("Download each copy of multipart object and validate it")
        for i in range(len(version_list)):
            c_scope_s3client.download_bucket_contents(
                bucket_name, results_dir, VersionId=version_list[i]
            )
            assert check_data_integrity(origin_dir, results_dir)
            log.info("Both uploaded and downloaded data are identical")
            os.remove(results_dir + "/" + object_name[0])
        # Copy versioned object to non-versioned bucket
        destination_bucket = c_scope_s3client.create_bucket()
        cp_response = c_scope_s3client.copy_object(
            bucket_name, object_name[0], destination_bucket, object_name[0]
        )
        assert (
            cp_response["ResponseMetadata"]["HTTPStatusCode"] == 200
        ), "Failed to copy object from versioned to non-versioned bucket"
        log.info(cp_response)
        c_scope_s3client.download_bucket_contents(destination_bucket, results_dir)
        assert check_data_integrity(origin_dir, results_dir)
        log.info("Copied data is identical with Uploaded data")
