import boto3
import datetime
from botocore.exceptions import ClientError, BotoCoreError
from typing import Dict, List, Any


class IAMAuditor:
    def __init__(self, profile_name: str = None):
        try:
            if profile_name:
                self.session = boto3.Session(profile_name=profile_name)
            else:
                self.session = boto3.Session()
            self.iam = self.session.client('iam')
        except Exception as e:
            raise RuntimeError(f"Failed to initialize AWS session: {str(e)}")

    def get_all_users(self) -> List[Dict[str, Any]]:
        """Retrieve all IAM users."""
        users = []
        try:
            paginator = self.iam.get_paginator('list_users')
            for page in paginator.paginate():
                users.extend(page['Users'])
        except (ClientError, BotoCoreError) as e:
            print(f"Error listing users: {e}")
        return users

    def check_mfa_enabled(self, user_name: str) -> bool:
        """Check if MFA is enabled for a user."""
        try:
            mfa_devices = self.iam.list_mfa_devices(UserName=user_name)
            return len(mfa_devices['MFADevices']) > 0
        except ClientError as e:
            # Если ошибка 'NoSuchEntity' (нет MFA) - это ок, возвращаем False
            if e.response['Error']['Code'] == 'NoSuchEntity':
                return False
            # Если любая ДРУГАЯ ошибка (нет прав, сеть и т.д.) - выводим её и возвращаем False с предупреждением
            else:
                error_code = e.response['Error']['Code']
                error_msg = e.response['Error']['Message']
                print(
                    f"⚠️  Error checking MFA for {user_name}: "
                    f"{error_code} - {error_msg}"
                )
                return False
        except BotoCoreError as e:
            print(f"⚠️  BotoCore error checking MFA for {user_name}: {e}")
            return False

    def check_old_access_keys(self, user_name: str, max_age_days: int = 90) -> List[Dict[str, Any]]:
        """Check for access keys older than max_age_days."""
        old_keys = []
        try:
            paginator = self.iam.get_paginator('list_access_keys')
            for page in paginator.paginate(UserName=user_name):
                for key in page['AccessKeyMetadata']:
                    create_date = key['CreateDate']
                    # Ensure timezone awareness compatibility
                    if create_date.tzinfo is None:
                        create_date = create_date.replace(tzinfo=datetime.timezone.utc)

                    age = (datetime.datetime.now(datetime.timezone.utc) - create_date).days
                    if age > max_age_days and key['Status'] == 'Active':
                        old_keys.append({
                            'AccessKeyId': key['AccessKeyId'],
                            'Age': age,
                            'CreateDate': create_date.isoformat()
                        })
        except (ClientError, BotoCoreError) as e:
            print(f"Error checking access keys for {user_name}: {e}")
        return old_keys

    def check_admin_access(self, user_name: str) -> bool:
        """Check if user has AdministratorAccess policy attached directly or via groups."""
        try:
            # Check attached user policies
            attached_policies = self.iam.list_attached_user_policies(UserName=user_name)
            for policy in attached_policies['AttachedPolicies']:
                if policy['PolicyName'] == 'AdministratorAccess':
                    return True

            # Check groups
            groups = self.iam.list_groups_for_user(UserName=user_name)
            for group in groups['Groups']:
                attached_group_policies = self.iam.list_attached_group_policies(GroupName=group['GroupName'])
                for policy in attached_group_policies['AttachedPolicies']:
                    if policy['PolicyName'] == 'AdministratorAccess':
                        return True
        except (ClientError, BotoCoreError) as e:
            print(f"Error checking admin access for {user_name}: {e}")
        return False

    def audit_user(self, user: Dict[str, Any]) -> Dict[str, Any]:
        """Run all checks for a single user."""
        user_name = user['UserName']
        return {
            'UserName': user_name,
            'MFA_Enabled': self.check_mfa_enabled(user_name),
            'Old_Access_Keys': self.check_old_access_keys(user_name),
            'Is_Admin': self.check_admin_access(user_name)
        }

    def run_audit(self) -> List[Dict[str, Any]]:
        """Run full audit for all users."""
        results = []
        users = self.get_all_users()
        for user in users:
            results.append(self.audit_user(user))
        return results
