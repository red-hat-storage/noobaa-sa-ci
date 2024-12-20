import logging
import random
from framework.customizations.marks import tier1
from utility.bucket_utils import list_all_versions_of_the_object

log = logging.getLogger(__name__)


class TestBucketVersioningOperations:
    """
    Test S3 Bucket versioning operations using NSFS
    """

    obj_name = "obj_1"
    obj_data = "Original data"

    def setup_versioned_bucket(self, c_scope_s3client):
        """
        Setup the versioned bucket

        Args:
            c_scope_s3client (Object):
        Return:
            string: Versioned Bucket name
        """
        # Create regular bucket
        bucket = c_scope_s3client.create_bucket()

        # enable bucket versioning
        c_scope_s3client.put_bucket_versioning(bucket, status="Enabled")
        log.info(f"Enabled bucket versioning on bucket {bucket}")

        return bucket

    @tier1
    def test_enable_disable_bucket_versioning(self, c_scope_s3client):
        """
        Test S3 Bucket versioning status:
        1. Create regular bucket
        2. Enable versioning on bucket
        3. Verify versioning is enabled on bucket
        4. Suspend versioning on bucket
        5. Verify versioning is suspended on bucket

        """
        # Create regular bucket and enable versioning on it
        bucket = self.setup_versioned_bucket(c_scope_s3client)

        # get bucket versioning status
        log.info("get versioning status after enabling it")
        response = c_scope_s3client.get_bucket_versioning(bucket)
        assert response["Status"] == "Enabled", "Versioning is not enabled on bucket"

        # Suspend bucket versioning
        c_scope_s3client.put_bucket_versioning(bucket, status="Suspended")
        log.info(f"Bucket versioning suspended on bucket {bucket}")

        # get bucket versioning status
        log.info("get versioning status after suspending it")
        response = c_scope_s3client.get_bucket_versioning(bucket)
        assert response["Status"] == "Suspended", "Versioning is not enabled on bucket"

    @tier1
    def test_get_object_version_id_from_versioned_bucket(self, c_scope_s3client):
        """
        Test version id of the object from versioned bucket:
        1. Create regular bucket
        2. Enable versioning on bucket
        3. Upload data in versioned bucket
        4. Get object metadata from the bucket
        5. Verify version id is assigned to object or not
        """

        # Create regular bucket and enable versioning on it
        bucket = self.setup_versioned_bucket(c_scope_s3client)

        # Upload data in versioned bucket
        log.info("Uploading data in versioned bucket")
        response = c_scope_s3client.put_object(bucket, self.obj_name, self.obj_data)
        code = response["Code"]
        assert code == 200, f"put_object failed with response code {code}"

        # Get object metadata from the bucket and verify version id is assigned to object or not
        response = c_scope_s3client.get_object(bucket, self.obj_name)
        assert response["VersionId"] is not None, "Version id is not assigned to object"
        version_id = response["VersionId"]
        log.info(f"Version id of object {self.obj_name} is {version_id}")

    @tier1
    def test_object_version_ids_from_versioned_bucket(self, c_scope_s3client):
        """
        Test version id of the versioned data of the object from versioned bucket:
        1. Create regular bucket
        2. Enable versioning on bucket
        3. Upload data in versioned bucket
        4. Get first object metadata from the bucket
        5. re-upload new data with same object key
        6. Get new object metadata from the bucket
        7. Verify that both version ids are different from metadata
        """

        # Create regular bucket and enable versioning on it
        bucket = self.setup_versioned_bucket(c_scope_s3client)

        # Upload data in versioned bucket
        log.info("Uploading data in versioned bucket")
        response = c_scope_s3client.put_object(bucket, self.obj_name, self.obj_data)
        assert (
            response["Code"] == 200
        ), f"put_object failed with response code {response['Code']}"
        old_version_id = response["VersionId"]

        # Upload new data with same object name in versioned bucket to populate different version id
        log.info("Uploading new data with same object name in versioned bucket")
        new_data = self.obj_data + " New data"
        response = c_scope_s3client.put_object(bucket, self.obj_name, new_data)
        assert (
            response["Code"] == 200
        ), f"put_object failed with response code {response['Code']}"
        new_version_id = response["VersionId"]
        # Verify that both version ids are different from metadata

        assert old_version_id != new_version_id, "Both Version ids are same"
        log.info(f"Old version id of object {self.obj_name} is {old_version_id}")
        log.info(f"New version id of object {self.obj_name} is {new_version_id}")

    @tier1
    def test_list_version_ids_from_versioned_bucket(self, c_scope_s3client):
        """
        Test list version ids of the object from versioned bucket:
        1. Create regular bucket
        2. Enable versioning on bucket
        3. Upload 10 versions of data in versioned bucket
        4. List all versions of the object
        5. Verify version id count is matching with uploaded versions
        """

        # Create regular bucket and enable versioning on it
        bucket = self.setup_versioned_bucket(c_scope_s3client)

        # Upload 10 copies of data with same object_key in versioned bucket
        log.info("Uploading data in versioned bucket")
        for i in range(10):
            current_data = self.obj_data + " " + str(i)
            response = c_scope_s3client.put_object(bucket, self.obj_name, current_data)
            assert (
                response["Code"] == 200
            ), f"put_object failed with response code {response['Code']}"

        # List all versions of the object
        version_list = list_all_versions_of_the_object(
            c_scope_s3client, bucket, self.obj_name
        )
        for v in version_list:
            log.info(v)
        assert (
            len(version_list) == 10
        ), f"Uploaded 10 copies and listed {len(version_list)} copies of data"
        log.info("Uploaded copies and listed copies count is same")

    @tier1
    def test_get_specific_version_of_the_object(self, c_scope_s3client):
        """
        Test list version ids of the object from versioned bucket:
        1. Create regular bucket
        2. Enable versioning on bucket
        3. Upload 5 versions of data in versioned bucket
        4. Get specific version of the object
        5. Verify the content of the object with original data
        """

        # Create regular bucket and enable versioning on it
        bucket = self.setup_versioned_bucket(c_scope_s3client)

        # Upload 5 copies of data with same object_key in versioned bucket
        log.info("Uploading data in versioned bucket")
        data_dic = {}
        for i in range(5):
            current_data = self.obj_data + " " + str(i)
            response = c_scope_s3client.put_object(bucket, self.obj_name, current_data)
            assert (
                response["Code"] == 200
            ), f"put_object failed with response code {response['Code']}"
            data_dic.update({response["VersionId"]: current_data})

        # Get specific version of the object
        ver_id = random.choice(list(data_dic.keys()))
        get_obj_data = (
            c_scope_s3client.get_object(bucket, self.obj_name, VersionId=ver_id)["Body"]
            .read()
            .decode("utf-8")
        )
        log.info(get_obj_data)

        # Verify the content of the object with original data
        assert (
            data_dic[ver_id] == get_obj_data
        ), "Original data and downloaded data does not match"
        log.info("Original data and downloaded data is identical")

    @tier1
    def test_delete_specific_version_of_the_object(self, c_scope_s3client):
        """
        Test list version ids of the object from versioned bucket:
        1. Create regular bucket
        2. Enable versioning on bucket
        3. Upload 2 versions of data in versioned bucket
        4. Delete first version of the object
        5. List all versions of the object
        6. Verify list returns only one version id of the object
        """
        # Create regular bucket and enable versioning on it
        bucket = self.setup_versioned_bucket(c_scope_s3client)

        # Upload 2 copies of data with same object_key in versioned bucket
        log.info("Uploading data in versioned bucket")
        for i in range(2):
            current_data = self.obj_data + " " + str(i)
            response = c_scope_s3client.put_object(bucket, self.obj_name, current_data)
            assert (
                response["Code"] == 200
            ), f"put_object failed with response code {response['Code']}"

        # List all versions of the object
        version_list = list_all_versions_of_the_object(
            c_scope_s3client, bucket, self.obj_name
        )
        for v in version_list:
            log.info(v)

        # delete first version of the object
        del_resp = c_scope_s3client.delete_object(
            bucket, self.obj_name, VersionId=version_list[0]
        )
        assert (
            del_resp["Code"] == 204
        ), f"delete_object resulted in an unexpected response: {del_resp}"

        # List all versions of the object after delete operaion
        version_list = list_all_versions_of_the_object(
            c_scope_s3client, bucket, self.obj_name
        )
        for v in version_list:
            log.info(v)
        assert (
            len(version_list) == 1
        ), f"Deletion of versioned object with version id failed"
        log.info("Successfully deleted versioned object with version id")

    @tier1
    def test_delete_restore_versioned_object(self, c_scope_s3client):
        """
        Test list version ids of the object from versioned bucket:
        1. Create regular bucket
        2. Enable versioning on bucket
        3. Upload object in versioned bucket
        4. Delete object without specifying version of the object
        5. Verify that the delete marker appears in version list
        6. Restore object by deleting delete marker for the object
        """
        # Create regular bucket and enable versioning on it
        bucket = self.setup_versioned_bucket(c_scope_s3client)

        # Upload data with object_key in versioned bucket
        log.info("Uploading data in versioned bucket")
        response = c_scope_s3client.put_object(bucket, self.obj_name, self.obj_data)
        assert (
            response["Code"] == 200
        ), f"put_object failed with response code {response['Code']}"

        # delete the object
        del_response = c_scope_s3client.delete_object(bucket, self.obj_name)
        assert (
            del_response["Code"] == 204
        ), f"delete_object resulted in an unexpected response: {del_response}"

        # Verify delete marker is added in version list of the object after delete operaion
        response = c_scope_s3client.list_object_versions(bucket)
        assert response["DeleteMarkers"][0]["VersionId"] == del_response.get(
            "VersionId"
        ), f"Delete marker is not added for object {self.obj_name}"
        log.info("Delete marker added successfully to the deleted object")

        # Restore object by deleting delete marker of the object
        restore_resp = c_scope_s3client.delete_object(
            bucket, self.obj_name, VersionId=del_response.get("VersionId")
        )
        assert (
            restore_resp["Code"] == 204
        ), f"delete_object resulted in an unexpected response: {del_response}"

        response = c_scope_s3client.list_object_versions(bucket)
        assert (
            response["Versions"][0]["Key"] == self.obj_name
            and response["Versions"][0]["IsLatest"] == True
        ), f"Not able to restore object after deleting Delete marker for object {self.obj_name}"

        restored_obj_data = (
            c_scope_s3client.get_object(bucket, self.obj_name)["Body"]
            .read()
            .decode("utf-8")
        )
        log.info(restored_obj_data)

        assert (
            self.obj_data == restored_obj_data
        ), "Original data and restored data does not match"
        log.info("Object restored successfully after deleting Delete marker")

    @tier1
    def test_suspend_version_overwrite_object(self, c_scope_s3client):
        """
        Test list version ids of the object from versioned bucket:
        1. Create regular bucket
        2. Enable versioning on bucket and suspend it
        3. Upload object in version suspended bucket
        4. overwrite the object with same key
        5. Verify that the only one version id is present for object
        """
        # Create regular bucket and enable versioning on it
        bucket = self.setup_versioned_bucket(c_scope_s3client)

        # Suspend bucket versioning on bucket
        c_scope_s3client.put_bucket_versioning(bucket, status="Suspended")
        log.info(f"Suspended bucket versioning on bucket {bucket}")

        # Upload data two times with same object_key in bucket
        log.info("Uploading data in suspended versioned bucket")
        for i in range(2):
            data = self.obj_data + " " + str(i)
            response = c_scope_s3client.put_object(bucket, self.obj_name, data)
            assert (
                response["Code"] == 200
            ), f"put_object failed with response code {response['Code']}"

        # List all versions of the object
        version_list = list_all_versions_of_the_object(
            c_scope_s3client, bucket, self.obj_name
        )
        assert (
            len(version_list) == 1 and version_list[0] == "null"
        ), "Overwrite object operation is failed on suspended versioned bucket"
        log.info(
            "Successfully completed the overwrite object operation on suspended versioned bucket"
        )

    @tier1
    def test_copy_op_from_versioned_to_non_versioned_bucket(self, c_scope_s3client):
        """
        Test multipart object operation on versioned bucket:
        1. Create two regular bucket
        2. Enable versioning on one bucket
        3. Upload object in version bucket
        4. Copy object from versioned bucket to non versioned bucket
        5. Download object from regular bucket and verify the data integrity of it
        """
        # Create regular bucket and enable versioning on it
        regular_bucket = c_scope_s3client.create_bucket()
        versioned_bucket = self.setup_versioned_bucket(c_scope_s3client)

        # Upload 3 copies of data in versioned bucket
        log.info("Uploading data in versioned bucket")
        for i in range(3):
            current_data = self.obj_data + " " + str(i)
            response = c_scope_s3client.put_object(
                versioned_bucket, self.obj_name, current_data
            )
            assert (
                response["Code"] == 200
            ), f"put_object failed with response code {response['Code']}"

        # Copy object from versioned bucket to non versioned bucket
        cp_response = c_scope_s3client.copy_object(
            versioned_bucket, self.obj_name, regular_bucket, self.obj_name
        )
        assert (
            cp_response["ResponseMetadata"]["HTTPStatusCode"] == 200
        ), "Failed to copy object from versioned to non-versioned bucket"
        log.info(cp_response)

        # Download object from regular bucket and verify the data integrity of it
        get_obj_data = (
            c_scope_s3client.get_object(regular_bucket, self.obj_name)["Body"]
            .read()
            .decode("utf-8")
        )
        log.info(get_obj_data)

        # Verify the content of the object with original data
        assert (
            current_data == get_obj_data
        ), "Original data and downloaded data does not match"
        log.info("Original data and downloaded data is identical")

    @tier1
    def test_head_object_op_of_the_object(self, c_scope_s3client):
        """
        Test Head Object operation of the specific versioned object bucket:
        1. Create regular bucket
        2. Enable versioning on bucket
        3. Upload 5 versions of data in versioned bucket
        4. Get metadata of the specific version of the object
        5. Verify ETags of uploaded content and head object response
        """

        # Create regular bucket and enable versioning on it
        bucket = self.setup_versioned_bucket(c_scope_s3client)

        # Upload 5 copies of data with same object_key in versioned bucket
        log.info("Uploading data in versioned bucket")
        data_dic = {}
        for i in range(5):
            current_data = self.obj_data + " " + str(i)
            response = c_scope_s3client.put_object(bucket, self.obj_name, current_data)
            assert (
                response["Code"] == 200
            ), f"put_object failed with response code {response['Code']}"
            data_dic.update({current_data: response})

        # Get metadata of specific versioned of the object
        resp = random.choice(list(data_dic.keys()))
        ver_id = data_dic[resp]["VersionId"]
        get_obj_metadata = c_scope_s3client.head_object(
            bucket, self.obj_name, VersionId=ver_id
        )
        log.info(get_obj_metadata)

        # Verify the content of the object with original data
        assert (
            data_dic[resp]["ETag"] == get_obj_metadata["ETag"]
        ), "Etags of uploaded Original data and Head object data does not match"
        log.info(
            "ETags of uploaded data response and head object response are identical"
        )
