#!/usr/bin/env python3
"""
Cloud IAM Optimizer - AWS/GCP IAM Least Privilege Auditor
Author: Ranas Mukminov (@ranas-mukminov)
Website: https://run-as-daemon.ru
License: MIT
"""

import argparse
import json
import sys
from datetime import datetime
from typing import Dict, List, Optional

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False

try:
    from google.cloud import iam_credentials
    from google.cloud import resourcemanager_v3
    GCP_AVAILABLE = False  # Will enable when google-cloud libraries are installed
except ImportError:
    GCP_AVAILABLE = False


class IAMOptimizer:
    """Main class for IAM analysis and optimization recommendations."""
    
    def __init__(self, provider: str = "aws", profile: Optional[str] = None):
        """
        Initialize IAM Optimizer.
        
        Args:
            provider: Cloud provider ('aws' or 'gcp')
            profile: AWS profile name (optional)
        """
        self.provider = provider.lower()
        self.profile = profile
        self.findings: List[Dict] = []
        
    def analyze_aws_iam(self) -> Dict:
        """
        Analyze AWS IAM users and their permissions.
        
        Returns:
            Dictionary with IAM analysis results
        """
        if not AWS_AVAILABLE:
            return {
                "error": "AWS SDK (boto3) not installed. Install with: pip install boto3",
                "provider": "aws",
                "timestamp": datetime.utcnow().isoformat()
            }
        
        try:
            # Initialize AWS session
            if self.profile:
                session = boto3.Session(profile_name=self.profile)
            else:
                session = boto3.Session()
            
            iam = session.client('iam')
            
            # Get all IAM users
            users_response = iam.list_users()
            users = users_response.get('Users', [])
            
            results = {
                "provider": "aws",
                "timestamp": datetime.utcnow().isoformat(),
                "total_users": len(users),
                "users": [],
                "findings": []
            }
            
            for user in users:
                user_name = user['UserName']
                user_data = {
                    "username": user_name,
                    "user_id": user.get('UserId'),
                    "created": user.get('CreateDate').isoformat() if user.get('CreateDate') else None,
                    "policies": {"managed": [], "inline": []},
                    "groups": [],
                    "access_keys": [],
                    "mfa_enabled": False
                }
                
                # Get attached managed policies
                try:
                    attached_policies = iam.list_attached_user_policies(UserName=user_name)
                    user_data['policies']['managed'] = [
                        p['PolicyArn'] for p in attached_policies.get('AttachedPolicies', [])
                    ]
                except ClientError:
                    pass
                
                # Get inline policies
                try:
                    inline_policies = iam.list_user_policies(UserName=user_name)
                    user_data['policies']['inline'] = inline_policies.get('PolicyNames', [])
                except ClientError:
                    pass
                
                # Get user groups
                try:
                    groups_response = iam.list_groups_for_user(UserName=user_name)
                    user_data['groups'] = [g['GroupName'] for g in groups_response.get('Groups', [])]
                except ClientError:
                    pass
                
                # Check access keys
                try:
                    keys_response = iam.list_access_keys(UserName=user_name)
                    user_data['access_keys'] = [
                        {
                            "access_key_id": key['AccessKeyId'],
                            "status": key['Status'],
                            "created": key.get('CreateDate').isoformat() if key.get('CreateDate') else None
                        }
                        for key in keys_response.get('AccessKeyMetadata', [])
                    ]
                except ClientError:
                    pass
                
                # Check MFA
                try:
                    mfa_devices = iam.list_mfa_devices(UserName=user_name)
                    user_data['mfa_enabled'] = len(mfa_devices.get('MFADevices', [])) > 0
                except ClientError:
                    pass
                
                results['users'].append(user_data)
                
                # Generate findings
                if not user_data['mfa_enabled'] and len(user_data['access_keys']) > 0:
                    results['findings'].append({
                        "severity": "HIGH",
                        "user": user_name,
                        "issue": "User has active access keys but MFA is not enabled",
                        "recommendation": "Enable MFA for all users with programmatic access"
                    })
                
                if 'AdministratorAccess' in str(user_data['policies']):
                    results['findings'].append({
                        "severity": "MEDIUM",
                        "user": user_name,
                        "issue": "User has AdministratorAccess policy",
                        "recommendation": "Review if full admin access is necessary, consider scoping down permissions"
                    })
            
            return results
            
        except NoCredentialsError:
            return {
                "error": "AWS credentials not configured. Configure with 'aws configure' or set AWS_* env vars",
                "provider": "aws",
                "timestamp": datetime.utcnow().isoformat()
            }
        except ClientError as e:
            return {
                "error": f"AWS API error: {str(e)}",
                "provider": "aws",
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            return {
                "error": f"Unexpected error: {str(e)}",
                "provider": "aws",
                "timestamp": datetime.utcnow().isoformat()
            }
    
    def analyze_gcp_iam(self) -> Dict:
        """
        Analyze GCP IAM users and their permissions.
        
        Returns:
            Dictionary with IAM analysis results
        """
        if not GCP_AVAILABLE:
            return {
                "error": "GCP SDK not installed. Install with: pip install google-cloud-iam google-cloud-resource-manager",
                "provider": "gcp",
                "timestamp": datetime.utcnow().isoformat(),
                "note": "GCP IAM analysis will be available in future versions"
            }
        
        # GCP implementation placeholder
        return {
            "provider": "gcp",
            "timestamp": datetime.utcnow().isoformat(),
            "note": "GCP IAM analysis coming soon"
        }
    
    def run_analysis(self) -> Dict:
        """
        Run IAM analysis based on selected provider.
        
        Returns:
            Analysis results dictionary
        """
        if self.provider == "aws":
            return self.analyze_aws_iam()
        elif self.provider == "gcp":
            return self.analyze_gcp_iam()
        else:
            return {
                "error": f"Unsupported provider: {self.provider}",
                "supported_providers": ["aws", "gcp"]
            }


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Cloud IAM Optimizer - AWS/GCP IAM Least Privilege Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze AWS IAM (using default credentials)
  python iam_optimizer.py --provider aws
  
  # Analyze AWS IAM with specific profile
  python iam_optimizer.py --provider aws --profile production
  
  # Output as JSON
  python iam_optimizer.py --provider aws --output json
  
  # Save results to file
  python iam_optimizer.py --provider aws --output json > iam_audit.json

Visit: https://run-as-daemon.ru for commercial support and enterprise features.
        """
    )
    
    parser.add_argument(
        "--provider",
        choices=["aws", "gcp"],
        default="aws",
        help="Cloud provider to analyze (default: aws)"
    )
    
    parser.add_argument(
        "--profile",
        help="AWS profile name (for AWS provider only)"
    )
    
    parser.add_argument(
        "--output",
        choices=["json", "text"],
        default="text",
        help="Output format (default: text)"
    )
    
    args = parser.parse_args()
    
    # Run analysis
    optimizer = IAMOptimizer(provider=args.provider, profile=args.profile)
    results = optimizer.run_analysis()
    
    # Output results
    if args.output == "json":
        print(json.dumps(results, indent=2, default=str))
    else:
        # Text output
        print(f"\n{'='*70}")
        print(f"Cloud IAM Optimizer - {args.provider.upper()} Analysis")
        print(f"{'='*70}")
        print(f"Timestamp: {results.get('timestamp', 'N/A')}")
        
        if 'error' in results:
            print(f"\n❌ ERROR: {results['error']}")
            if 'note' in results:
                print(f"ℹ️  {results['note']}")
            sys.exit(1)
        
        print(f"\nTotal Users: {results.get('total_users', 0)}")
        
        # Display users
        if results.get('users'):
            print(f"\n{'─'*70}")
            print("IAM Users:")
            print(f"{'─'*70}")
            for user in results['users']:
                print(f"\n👤 {user['username']}")
                print(f"   User ID: {user.get('user_id', 'N/A')}")
                print(f"   Created: {user.get('created', 'N/A')}")
                print(f"   MFA Enabled: {'✅ Yes' if user.get('mfa_enabled') else '❌ No'}")
                print(f"   Groups: {', '.join(user.get('groups', [])) or 'None'}")
                print(f"   Managed Policies: {len(user.get('policies', {}).get('managed', []))}")
                print(f"   Inline Policies: {len(user.get('policies', {}).get('inline', []))}")
                print(f"   Access Keys: {len(user.get('access_keys', []))}")
        
        # Display findings
        if results.get('findings'):
            print(f"\n{'─'*70}")
            print("Security Findings:")
            print(f"{'─'*70}")
            for finding in results['findings']:
                severity_icon = "🔴" if finding['severity'] == "HIGH" else "🟡"
                print(f"\n{severity_icon} [{finding['severity']}] {finding['user']}")
                print(f"   Issue: {finding['issue']}")
                print(f"   Recommendation: {finding['recommendation']}")
        else:
            print(f"\n✅ No security findings detected")
        
        print(f"\n{'='*70}")
        print("For enterprise features and commercial support:")
        print("🌐 https://run-as-daemon.ru")
        print("📧 Contact: @ranas-mukminov")
        print(f"{'='*70}\n")


if __name__ == "__main__":
    main()
