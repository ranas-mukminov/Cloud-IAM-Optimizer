import boto3
import datetime
from botocore.exceptions import ClientError

# Настройки: Считать ключи старыми, если им больше X дней
DAYS_LIMIT = 90

def get_iam_client():
    return boto3.client('iam')

def audit_users():
    client = get_iam_client()
    users = client.list_users()['Users']
    
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
                print(f"    ⚠️  Error checking MFA for {username}: {e.response['Error']['Code']} - {e.response['Error']['Message']}")
                mfa_check_failed = True

        # 2. Проверка ключей доступа
        keys = client.list_access_keys(UserName=username)['AccessKeyMetadata']
        key_status = "No Keys"
        
        if keys:
            for key in keys:
                create_date = key['CreateDate'].replace(tzinfo=None)
                age = (datetime.datetime.now() - create_date).days
                if age > DAYS_LIMIT:
                    key_status = f"⚠️ OLD ({age}d)"
                else:
                    key_status = f"✅ OK ({age}d)"

        # Вывод
        if mfa_check_failed:
            mfa_str = "⚠️  ERROR"
        else:
            mfa_str = "✅ ON" if mfa_enabled else "❌ OFF"
        print(f"{username:<25} | {mfa_str:<10} | {key_status:<15} | {'🚨 ALERT' if not mfa_enabled or 'OLD' in key_status else 'OK'}")

if __name__ == "__main__":
    print("🚀 Starting Cloud IAM Audit...\n")
    audit_users()
