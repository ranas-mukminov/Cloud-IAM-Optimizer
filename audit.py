import boto3
import datetime
from botocore.exceptions import ClientError

# Настройки: Считать ключи старыми, если им больше X дней
DAYS_LIMIT = 90


def get_iam_client():
    """Initialize and return an AWS IAM client."""
    return boto3.client('iam')


def audit_users():
    """Run IAM security audit for all users."""
    client = get_iam_client()

    # Get all users with pagination and error handling
    try:
        paginator = client.get_paginator('list_users')
        users = []
        for page in paginator.paginate():
            users.extend(page['Users'])
    except ClientError as e:
        print(f"🚨 FATAL: Cannot list IAM users: {e.response['Error']['Code']}")
        print(f"   Message: {e.response['Error']['Message']}")
        print("\nPlease ensure you have 'iam:ListUsers' permission.")
        return

    print(f"{'USER':<25} | {'MFA':<10} | {'KEY AGE (Days)':<15} | {'STATUS'}")
    print("-" * 70)

    for user in users:
        username = user['UserName']

        # 1. Проверка MFA
        mfa_enabled = False
        mfa_check_failed = False
        try:
            mfa = client.list_mfa_devices(UserName=username)
            if mfa['MFADevices']:
                mfa_enabled = True
        except ClientError as e:
            # Если ошибка 'NoSuchEntity' (нет MFA) - это ок, просто идем дальше
            if e.response['Error']['Code'] == 'NoSuchEntity':
                mfa_enabled = False
            # Если любая ДРУГАЯ ошибка (нет прав, сеть и т.д.) - выводим её
            else:
                error_code = e.response['Error']['Code']
                error_msg = e.response['Error']['Message']
                print(
                    f"    ⚠️  Error checking MFA for {username}: "
                    f"{error_code} - {error_msg}"
                )
                mfa_check_failed = True

        # 2. Проверка ключей доступа
        key_status = "No Keys"
        key_check_failed = False
        try:
            keys = client.list_access_keys(UserName=username)['AccessKeyMetadata']
            if keys:
                statuses = []
                for key in keys:
                    create_date = key['CreateDate'].replace(tzinfo=None)
                    age = (datetime.datetime.now() - create_date).days
                    if age > DAYS_LIMIT:
                        statuses.append(f"⚠️ {age}d")
                    else:
                        statuses.append(f"✅ {age}d")
                key_status = ", ".join(statuses)
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_msg = e.response['Error']['Message']
            print(
                f"    ⚠️  Error checking keys for {username}: "
                f"{error_code} - {error_msg}"
            )
            key_status = "⚠️ ERROR"
            key_check_failed = True

        # Вывод
        if mfa_check_failed:
            mfa_str = "⚠️ ERROR"
        else:
            mfa_str = "✅ ON" if mfa_enabled else "❌ OFF"

        # Определение статуса
        if mfa_check_failed or key_check_failed:
            status = '⚠️ CHECK_FAILED'
        elif not mfa_enabled or 'OLD' in key_status or '⚠️' in key_status:
            status = '🚨 ALERT'
        else:
            status = 'OK'

        print(f"{username:<25} | {mfa_str:<10} | {key_status:<15} | {status}")


if __name__ == "__main__":
    print("🚀 Starting Cloud IAM Audit...\n")
    audit_users()
