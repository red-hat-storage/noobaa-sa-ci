import logging

from common_ci_utils.random_utils import (
    generate_unique_resource_name,
    generate_random_files,
)
from noobaa_sa import constants
from utility.utils import (
    check_data_integrity,
    split_file_data_for_multipart_upload,
    generate_random_key,
)

log = logging.getLogger(__name__)


def test_s3_multipart_operations(
    account_manager,
    s3_client_factory,
    tmp_directories_factory,
):
    """

    Test basic s3 operations using a noobaa bucket:
    1. Create an account
    2. Create a bucket using S3
    3. Write multipart objects to the bucket
    4. List multipart objects from the bucket
    5. Download the objects from the bucket and verify data integrity
    TODO 6. Delete the bucket along with objects using S3

    """

    origin_dir, results_dir = tmp_directories_factory(
        dirs_to_create=["origin", "result"]
    )

    # 1. Create an account using Node CLI
    account_name = generate_unique_resource_name(prefix="account")
    access_key = generate_random_key(constants.EXPECTED_ACCESS_KEY_LEN)
    secret_key = generate_random_key(constants.EXPECTED_SECRET_KEY_LEN)
    account_manager.create(account_name, access_key, secret_key)
    s3_client = s3_client_factory(access_and_secret_keys_tuple=(access_key, secret_key))
    # 2. Create a bucket using S3
    bucket_name = s3_client.create_bucket()
    assert bucket_name in s3_client.list_buckets(), "Bucket was not created"
    log.info("Bucket created successfully")

    # 3. Write multipart objects to the bucket
    object_names = generate_random_files(
        origin_dir,
        amount=1,
        min_size="20M",
        max_size="30M",
    )
    # Upload multipart object
    for i in range(len(object_names)):
        get_upload_id = s3_client.initiate_multipart_object_upload(
            bucket_name,
            object_names[i],
        )
        all_part_info = []
        file_name = origin_dir + "/" + object_names[i]
        part_size = "10M"
        part_data = split_file_data_for_multipart_upload(file_name, part_size)

        for pd in range(len(part_data)):
            part_id = pd + 1
            part_info = s3_client.initiate_upload_part(
                bucket_name,
                object_names[i],
                part_id,
                get_upload_id,
                part_data[pd],
            )
            all_part_info.append({"PartNumber": part_id, "ETag": part_info["ETag"]})
        list_mp_uploads = s3_client.list_multipart_upload(bucket_name)
        log.info(list_mp_uploads)
        mp_response = s3_client.complete_multipart_object_upload(
            bucket_name, object_names[i], get_upload_id, all_part_info
        )
        assert (
            mp_response["ResponseMetadata"]["HTTPStatusCode"] == 200
        ), "Failed to upload multipart object"
        log.info(mp_response)

    # 4. List multipart objects from the bucket
    listed_objs = s3_client.list_objects(bucket_name)
    assert set(object_names).issubset(
        set(listed_objs)
    ), "All uploaded objects are not present in bucket"

    # 5. Download the objects from the bucket and verify data integrity
    s3_client.download_bucket_contents(bucket_name, results_dir)
    assert check_data_integrity(origin_dir, results_dir)
