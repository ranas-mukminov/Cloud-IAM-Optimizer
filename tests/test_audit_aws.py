"""
Unit tests for audit_aws.py module.
Tests exception handling, MFA checks, and error scenarios.
"""
import unittest
from unittest.mock import Mock, patch, MagicMock
from botocore.exceptions import ClientError, BotoCoreError
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.audit_aws import IAMAuditor


class TestIAMAuditorMFAChecks(unittest.TestCase):
    """Test MFA checking logic with various error scenarios."""

    def setUp(self):
        """Set up test fixtures."""
        with patch('boto3.Session'):
            self.auditor = IAMAuditor()
            self.auditor.iam = Mock()

    def test_mfa_enabled_when_devices_exist(self):
        """Test that MFA is correctly identified as enabled."""
        self.auditor.iam.list_mfa_devices.return_value = {
            'MFADevices': [{'SerialNumber': 'arn:aws:iam::123456789012:mfa/user'}]
        }
        result = self.auditor.check_mfa_enabled('testuser')
        self.assertTrue(result)

    def test_mfa_disabled_when_no_devices(self):
        """Test that MFA is correctly identified as disabled."""
        self.auditor.iam.list_mfa_devices.return_value = {
            'MFADevices': []
        }
        result = self.auditor.check_mfa_enabled('testuser')
        self.assertFalse(result)

    def test_mfa_nosuchentity_returns_false(self):
        """Test NoSuchEntity error returns False (not an error)."""
        error_response = {
            'Error': {
                'Code': 'NoSuchEntity',
                'Message': 'The user does not have MFA'
            }
        }
        self.auditor.iam.list_mfa_devices.side_effect = ClientError(
            error_response, 'ListMFADevices'
        )
        result = self.auditor.check_mfa_enabled('testuser')
        self.assertFalse(result)

    @patch('builtins.print')
    def test_mfa_access_denied_prints_warning(self, mock_print):
        """Test AccessDenied error prints warning and returns False."""
        error_response = {
            'Error': {
                'Code': 'AccessDenied',
                'Message': 'User is not authorized'
            }
        }
        self.auditor.iam.list_mfa_devices.side_effect = ClientError(
            error_response, 'ListMFADevices'
        )
        result = self.auditor.check_mfa_enabled('testuser')
        self.assertFalse(result)
        # Verify warning was printed
        mock_print.assert_called_once()
        self.assertIn('AccessDenied', mock_print.call_args[0][0])

    @patch('builtins.print')
    def test_mfa_throttling_prints_warning(self, mock_print):
        """Test Throttling error prints warning and returns False."""
        error_response = {
            'Error': {
                'Code': 'Throttling',
                'Message': 'Rate exceeded'
            }
        }
        self.auditor.iam.list_mfa_devices.side_effect = ClientError(
            error_response, 'ListMFADevices'
        )
        result = self.auditor.check_mfa_enabled('testuser')
        self.assertFalse(result)
        # Verify warning was printed
        mock_print.assert_called_once()
        self.assertIn('Throttling', mock_print.call_args[0][0])

    @patch('builtins.print')
    def test_mfa_botocore_error_prints_warning(self, mock_print):
        """Test BotoCoreError prints warning and returns False."""
        self.auditor.iam.list_mfa_devices.side_effect = BotoCoreError()
        result = self.auditor.check_mfa_enabled('testuser')
        self.assertFalse(result)
        mock_print.assert_called_once()


class TestIAMAuditorKeyChecks(unittest.TestCase):
    """Test access key age checking logic."""

    def setUp(self):
        """Set up test fixtures."""
        with patch('boto3.Session'):
            self.auditor = IAMAuditor()
            self.auditor.iam = Mock()

    def test_old_keys_detection(self):
        """Test that old keys are correctly identified."""
        from datetime import datetime, timezone, timedelta

        old_date = datetime.now(timezone.utc) - timedelta(days=100)
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [{
            'AccessKeyMetadata': [{
                'AccessKeyId': 'AKIAIOSFODNN7EXAMPLE',
                'CreateDate': old_date,
                'Status': 'Active'
            }]
        }]
        self.auditor.iam.get_paginator.return_value = mock_paginator

        result = self.auditor.check_old_access_keys('testuser', max_age_days=90)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['AccessKeyId'], 'AKIAIOSFODNN7EXAMPLE')

    def test_recent_keys_not_flagged(self):
        """Test that recent keys are not flagged as old."""
        from datetime import datetime, timezone, timedelta

        recent_date = datetime.now(timezone.utc) - timedelta(days=30)
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [{
            'AccessKeyMetadata': [{
                'AccessKeyId': 'AKIAIOSFODNN7EXAMPLE',
                'CreateDate': recent_date,
                'Status': 'Active'
            }]
        }]
        self.auditor.iam.get_paginator.return_value = mock_paginator

        result = self.auditor.check_old_access_keys('testuser', max_age_days=90)
        self.assertEqual(len(result), 0)


class TestIAMAuditorAdminChecks(unittest.TestCase):
    """Test admin access detection logic."""

    def setUp(self):
        """Set up test fixtures."""
        with patch('boto3.Session'):
            self.auditor = IAMAuditor()
            self.auditor.iam = Mock()

    def test_direct_admin_policy_detected(self):
        """Test that direct AdministratorAccess policy is detected."""
        self.auditor.iam.list_attached_user_policies.return_value = {
            'AttachedPolicies': [
                {'PolicyName': 'AdministratorAccess'}
            ]
        }
        result = self.auditor.check_admin_access('testuser')
        self.assertTrue(result)

    def test_group_admin_policy_detected(self):
        """Test that AdministratorAccess via group is detected."""
        self.auditor.iam.list_attached_user_policies.return_value = {
            'AttachedPolicies': []
        }
        self.auditor.iam.list_groups_for_user.return_value = {
            'Groups': [{'GroupName': 'Admins'}]
        }
        self.auditor.iam.list_attached_group_policies.return_value = {
            'AttachedPolicies': [
                {'PolicyName': 'AdministratorAccess'}
            ]
        }
        result = self.auditor.check_admin_access('testuser')
        self.assertTrue(result)


if __name__ == '__main__':
    unittest.main()
