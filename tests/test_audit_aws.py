"""
Unit tests for audit_aws.py module.
Aligned with the current IAMAuditor API (check_mfa, check_keys, tuple admin).
"""
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch

from botocore.exceptions import ClientError

from src.audit_aws import AccessKey, IAMAuditor


def _make_auditor():
    """Construct IAMAuditor with a mocked boto3 IAM client."""
    with patch("src.audit_aws.boto3.client") as mock_client:
        mock_iam = Mock()
        mock_client.return_value = mock_iam
        mock_iam.get_user.return_value = {"User": {"UserName": "caller"}}
        auditor = IAMAuditor()
        auditor.iam = mock_iam
        return auditor


class TestIAMAuditorMFAChecks(unittest.TestCase):
    """Test MFA checking logic against check_mfa()."""

    def setUp(self):
        self.auditor = _make_auditor()

    def test_mfa_enabled_when_devices_exist(self):
        self.auditor.iam.list_mfa_devices.return_value = {
            "MFADevices": [{"SerialNumber": "arn:aws:iam::123456789012:mfa/user"}]
        }
        self.assertTrue(self.auditor.check_mfa("testuser"))

    def test_mfa_disabled_when_no_devices(self):
        self.auditor.iam.list_mfa_devices.return_value = {"MFADevices": []}
        self.assertFalse(self.auditor.check_mfa("testuser"))

    def test_mfa_client_error_returns_false(self):
        """ClientError from the API wrapper surfaces as False."""
        error_response = {
            "Error": {"Code": "NoSuchEntity", "Message": "The user does not have MFA"}
        }
        self.auditor._get_api_call = Mock(
            side_effect=ClientError(error_response, "ListMFADevices")
        )
        self.assertFalse(self.auditor.check_mfa("testuser"))

    def test_mfa_access_denied_returns_false(self):
        error_response = {
            "Error": {"Code": "AccessDenied", "Message": "User is not authorized"}
        }
        self.auditor._get_api_call = Mock(
            side_effect=ClientError(error_response, "ListMFADevices")
        )
        self.assertFalse(self.auditor.check_mfa("testuser"))


class TestIAMAuditorKeyChecks(unittest.TestCase):
    """Test access key age checking via check_keys()."""

    def setUp(self):
        self.auditor = _make_auditor()

    def test_old_keys_detection(self):
        old_date = datetime.now(timezone.utc) - timedelta(days=100)
        self.auditor.iam.list_access_keys.return_value = {
            "AccessKeyMetadata": [
                {
                    "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                    "CreateDate": old_date,
                    "Status": "Active",
                }
            ]
        }
        result = self.auditor.check_keys("testuser")
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], AccessKey)
        self.assertEqual(result[0].access_key_id, "AKIAIOSFODNN7EXAMPLE")
        self.assertTrue(result[0].is_old)
        self.assertGreaterEqual(result[0].age_days, 100)

    def test_recent_keys_not_flagged(self):
        recent_date = datetime.now(timezone.utc) - timedelta(days=30)
        self.auditor.iam.list_access_keys.return_value = {
            "AccessKeyMetadata": [
                {
                    "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                    "CreateDate": recent_date,
                    "Status": "Active",
                }
            ]
        }
        result = self.auditor.check_keys("testuser")
        self.assertEqual(len(result), 1)
        self.assertFalse(result[0].is_old)

    def test_no_keys_returns_empty(self):
        self.auditor.iam.list_access_keys.return_value = {"AccessKeyMetadata": []}
        self.assertEqual(self.auditor.check_keys("testuser"), [])


class TestIAMAuditorAdminChecks(unittest.TestCase):
    """Test admin access detection; returns (managed, inline) tuple."""

    def setUp(self):
        self.auditor = _make_auditor()

    def test_direct_admin_policy_detected(self):
        self.auditor.iam.list_attached_user_policies.return_value = {
            "AttachedPolicies": [{"PolicyName": "AdministratorAccess"}]
        }
        self.auditor.iam.list_groups_for_user.return_value = {"Groups": []}
        self.auditor.iam.list_user_policies.return_value = {"PolicyNames": []}

        managed, inline = self.auditor.check_admin_access("testuser")
        self.assertTrue(managed)
        self.assertFalse(inline)

    def test_group_admin_policy_detected(self):
        self.auditor.iam.list_attached_user_policies.return_value = {
            "AttachedPolicies": []
        }
        self.auditor.iam.list_groups_for_user.return_value = {
            "Groups": [{"GroupName": "Admins"}]
        }
        self.auditor.iam.list_attached_group_policies.return_value = {
            "AttachedPolicies": [{"PolicyName": "AdministratorAccess"}]
        }
        self.auditor.iam.list_group_policies.return_value = {"PolicyNames": []}
        self.auditor.iam.list_user_policies.return_value = {"PolicyNames": []}

        managed, inline = self.auditor.check_admin_access("testuser")
        self.assertTrue(managed)
        self.assertFalse(inline)

    def test_no_admin_returns_false_tuple(self):
        self.auditor.iam.list_attached_user_policies.return_value = {
            "AttachedPolicies": [{"PolicyName": "ReadOnlyAccess"}]
        }
        self.auditor.iam.list_groups_for_user.return_value = {"Groups": []}
        self.auditor.iam.list_user_policies.return_value = {"PolicyNames": []}

        managed, inline = self.auditor.check_admin_access("testuser")
        self.assertFalse(managed)
        self.assertFalse(inline)


class TestCLIWiring(unittest.TestCase):
    """Smoke tests for src/main.py dispatch."""

    def test_gcp_exits_nonzero(self):
        from click.testing import CliRunner
        from src.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["audit", "--provider", "gcp"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("not implemented", result.output.lower() + result.stderr.lower())


if __name__ == "__main__":
    unittest.main()
