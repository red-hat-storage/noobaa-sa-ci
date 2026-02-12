from framework.bucket_policies.bucket_policy import BucketPolicyBuilder
from framework.bucket_policies.s3_operation_access_tester import S3OperationAccessTester
from framework.customizations.marks import tier1


class TestNotBucketPolicies:
    """
    Test bucket policies that use the NotPrincipal, NotAction, and NotResource fields

    """

    @tier1
    def test_not_principal_bucket_policy(
        self, c_scope_s3client, account_manager, s3_client_factory
    ):
        """
        Test the NotPrincipal field in a bucket policy:
        1. Setup:
            1.1 Create a bucket using the admin client
            1.2 Create two accounts
        2. Apply a policy with:
            2.1 Allow statement: explicitly allow the allowed account for all actions
            2.2 Deny statement: deny GetObject for everyone except the allowed account (using NotPrincipal)
        3. Check that the allowed account can access the bucket
        4. Check that the denied account cannot access the bucket

        """
        # 1. Setup
        bucket = c_scope_s3client.create_bucket()
        allowed_acc_name, allowed_access_key, allowed_secret_key = (
            account_manager.create()
        )
        allowed_client = s3_client_factory(
            access_and_secret_keys_tuple=(allowed_access_key, allowed_secret_key)
        )
        denied_acc_name, denied_access_key, denied_secret_key = account_manager.create()
        denied_client = s3_client_factory(
            access_and_secret_keys_tuple=(denied_access_key, denied_secret_key)
        )

        # 2. Apply a policy with Allow statement using Principal and Deny statement using NotPrincipal
        policy = (
            BucketPolicyBuilder()
            .add_allow_statement()
            .add_principal(allowed_acc_name)
            .add_action("*")
            .add_resource(f"{bucket}")
            .add_resource(f"{bucket}/*")
            .add_deny_statement()
            .add_not_principal(allowed_acc_name)
            .add_action("GetObject")
            .add_resource(f"{bucket}")
            .add_resource(f"{bucket}/*")
            .build()
        )

        response = c_scope_s3client.put_bucket_policy(bucket, str(policy))
        assert (
            response["Code"] == 200
        ), f"put_bucket_policy failed with code {response['Code']}"

        # 3. Check that the allowed account can access the bucket
        access_tester = S3OperationAccessTester(
            admin_client=c_scope_s3client,
        )
        assert access_tester.check_client_access_to_bucket_op(
            allowed_client, bucket, "GetObject"
        ), "Access was denied for the allowed account"

        # 4. Check that the denied account cannot access the bucket
        assert not access_tester.check_client_access_to_bucket_op(
            denied_client, bucket, "GetObject"
        ), "The denied account was allowed access when it shouldn't have been"

    @tier1
    def test_not_action_bucket_policy(self, c_scope_s3client, s3_client_factory):
        """
        Test the NotAction field in a bucket policy:
        1. Setup:
            1.1 Create a bucket using the admin client
            1.2 Create a new account
        2. Allow all actions on the bucket's objects except for DeleteObject
        3. Check that the DeleteObject action is denied
        4. Check that other operations are allowed

        """
        # 1. Setup
        bucket = c_scope_s3client.create_bucket()
        new_acc_client = s3_client_factory()

        # 2. Allow all actions on the bucket's objects except for DeleteObject
        policy = (
            BucketPolicyBuilder()
            .add_allow_statement()
            .add_resource(f"{bucket}/*")
            .add_principal("*")
            .add_not_action("DeleteObject")
            .build()
        )

        response = c_scope_s3client.put_bucket_policy(bucket, str(policy))
        assert (
            response["Code"] == 200
        ), f"put_bucket_policy failed with code {response['Code']}"

        # 3. Check that the DeleteObject action is denied
        access_tester = S3OperationAccessTester(
            admin_client=c_scope_s3client,
        )
        assert not access_tester.check_client_access_to_bucket_op(
            new_acc_client, bucket, "DeleteObject"
        ), "DeleteObject was allowed when it should have been denied"

        # 4. Check that other actions are allowed
        for op in ["GetObject", "PutObject"]:
            assert access_tester.check_client_access_to_bucket_op(
                new_acc_client, bucket, op
            ), f"{op} was denied when it shouldn't have been"

    @tier1
    def test_not_resource_bucket_policy(self, c_scope_s3client, s3_client_factory):
        """
        Test the NotResource field in a bucket policy:
        1. Setup:
            1.1 Create a bucket using the admin client
            1.2 Create a new account
        2. Allow access to all objects on the bucket except for the object specified by NotResource
        3. Check that the object specified by NotResource is still inaccessible
        4. Check that access to the other object is allowed

        """
        # 1. Setup
        bucket = c_scope_s3client.create_bucket()
        new_acc_client = s3_client_factory()
        access_tester = S3OperationAccessTester(
            admin_client=c_scope_s3client,
        )

        denied_obj, allowed_obj = c_scope_s3client.put_random_objects(bucket, 2)

        # 2. Allow access to all objects on the bucket except for the
        # object specified by NotResource
        policy = (
            BucketPolicyBuilder()
            .add_allow_statement()
            .add_action("*")
            .add_principal("*")
            .add_not_resource(f"{bucket}/{denied_obj}")
            .build()
        )

        response = c_scope_s3client.put_bucket_policy(bucket, str(policy))
        assert (
            response["Code"] == 200
        ), f"put_bucket_policy failed with code {response['Code']}"

        # 3. Check that the object specified by NotResource is still inaccessible
        assert not access_tester.check_client_access_to_bucket_op(
            new_acc_client, bucket, "GetObject", obj_key=denied_obj
        ), f"Access to {denied_obj} was allowed when it should have been denied"

        # 4. Check that access to the other object is allowed
        assert access_tester.check_client_access_to_bucket_op(
            new_acc_client, bucket, "GetObject", obj_key=allowed_obj
        ), f"Acess to {allowed_obj} was denied when it should have been allowed"
