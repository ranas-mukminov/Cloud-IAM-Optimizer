import boto3
import datetime
import sys
from botocore.exceptions import ClientError, NoCredentialsError

# Настройки
DAYS_LIMIT = 90


def get_iam_client():
    # Пытаемся создать клиента.
    # Если нет ключей — падаем сразу с понятной ошибкой.
    try:
        return boto3.client('iam')
    except NoCredentialsError:
        print("❌ ERROR: No AWS credentials found.")
        print(
            "   Please configure them via 'aws configure' or set "
            "AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY."
        )
        sys.exit(1)


def audit_users():
    client = get_iam_client()

    try:
        users = client.list_users()['Users']
    except ClientError as e:
        print(
            f"❌ CRITICAL ERROR: Could not list users. Check permissions.\n"
            f"   Details: {e}"
        )
        sys.exit(1)
    except NoCredentialsError:
        print("❌ ERROR: No AWS credentials found.")
        print(
            "   Please configure them via 'aws configure' or set "
            "AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY."
        )
        sys.exit(1)

    # Шапка таблицы
    print(f"{'USER':<25} | {'MFA':<10} | {'KEY AGE (Days)':<15} | {'STATUS'}")
    print("-" * 75)

    for user in users:
        username = user['UserName']
        mfa_status = "❓ ERROR"
        key_status = "❓ ERROR"
        is_alert = False

        # --- 1. Проверка MFA ---
        try:
            # list_mfa_devices не падает, если MFA нет,
            # он просто возвращает пустой список.
            # Ошибки тут - это реальные проблемы с правами.
            response = client.list_mfa_devices(UserName=username)
            if response['MFADevices']:
                mfa_status = "✅ ON"
            else:
                mfa_status = "❌ OFF"
                is_alert = True
        except ClientError as e:
            # Если ошибка прав доступа или другая - выводим код ошибки
            error_code = e.response['Error']['Code']
            mfa_status = f"⚠️ {error_code}"
            is_alert = True

        # --- 2. Проверка ключей доступа ---
        try:
            keys = client.list_access_keys(
                UserName=username
            )['AccessKeyMetadata']
            if not keys:
                key_status = "No Keys"
            else:
                # Берем самый старый ключ
                oldest_age = 0
                for key in keys:
                    create_date = key['CreateDate'].replace(tzinfo=None)
                    age = (datetime.datetime.now() - create_date).days
                    if age > oldest_age:
                        oldest_age = age

                if oldest_age > DAYS_LIMIT:
                    key_status = f"⚠️ OLD ({oldest_age}d)"
                    is_alert = True
                else:
                    key_status = f"✅ OK ({oldest_age}d)"

        except ClientError:
            key_status = "⚠️ Err"

        # --- Вывод строки ---
        row_status = "🚨 ALERT" if is_alert else "OK"
        print(
            f"{username:<25} | {mfa_status:<10} | "
            f"{key_status:<15} | {row_status}"
        )


if __name__ == "__main__":
    print("🚀 Starting Cloud IAM Audit...\n")
    audit_users()
