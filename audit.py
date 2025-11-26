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
        try:
            mfa = client.list_mfa_devices(UserName=username)
            if mfa['MFADevices']:
                mfa_enabled = True
        except ClientError:
            pass

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
        mfa_str = "✅ ON" if mfa_enabled else "❌ OFF"
        print(f"{username:<25} | {mfa_str:<10} | {key_status:<15} | {'🚨 ALERT' if not mfa_enabled or 'OLD' in key_status else 'OK'}")

if __name__ == "__main__":
    print("🚀 Starting Cloud IAM Audit...\n")
    audit_users()
