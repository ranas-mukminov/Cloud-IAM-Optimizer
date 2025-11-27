import boto3
import logging
import concurrent.futures
from datetime import datetime, timezone
from typing import List, Optional, Any
from botocore.exceptions import ClientError, NoCredentialsError
from pydantic import BaseModel, Field
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

# --- Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("IAMAuditor")

DAYS_LIMIT = 90


# --- Pydantic Models ---
class AccessKey(BaseModel):
    access_key_id: str
    age_days: int
    status: str
    is_old: bool

class UserAudit(BaseModel):
    username: str
    mfa_enabled: bool
    keys: List[AccessKey] = Field(default_factory=list)
    is_admin: bool
    has_inline_admin: bool = False
    error: Optional[str] = None

    @property
    def status(self) -> str:
        if self.error:
            return "ERROR"
        if self.is_admin or self.has_inline_admin:
            return "ADMIN"
        if not self.mfa_enabled:
            return "NO_MFA"
        if any(k.is_old for k in self.keys):
            return "OLD_KEYS"
        return "OK"


# --- Auditor Class ---
class IAMAuditor:
    def __init__(self, max_workers: int = 10):
        self.max_workers = max_workers
        try:
            self.iam = boto3.client('iam')
            # Verify credentials early
            self.iam.get_user()
        except NoCredentialsError:
            logger.critical("No AWS credentials found. Please configure them.")
            raise
        except ClientError as e:
            # If we can't get our own user, we might still have list permissions, 
            # but it's good to log.
            logger.warning(f"Could not verify identity: {e}")

    @retry(
        retry=retry_if_exception_type(ClientError),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    def _get_api_call(self, func, **kwargs):
        """Wrapper for AWS API calls with retry logic for throttling."""
        try:
            return func(**kwargs)
        except ClientError as e:
            if e.response['Error']['Code'] == 'Throttling':
                logger.warning("Throttling detected, retrying...")
                raise e
            raise

    def get_all_users(self) -> List[str]:
        """Fetch all IAM usernames."""
        users = []
        try:
            paginator = self.iam.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page['Users']:
                    users.append(user['UserName'])
        except ClientError as e:
            logger.error(f"Failed to list users: {e}")
            raise
        return users

    def check_mfa(self, username: str) -> bool:
        try:
            response = self._get_api_call(self.iam.list_mfa_devices, UserName=username)
            return len(response['MFADevices']) > 0
        except ClientError as e:
            logger.error(f"Error checking MFA for {username}: {e}")
            return False

    def check_keys(self, username: str) -> List[AccessKey]:
        keys = []
        try:
            response = self._get_api_call(self.iam.list_access_keys, UserName=username)
            for k in response['AccessKeyMetadata']:
                create_date = k['CreateDate']
                if create_date.tzinfo is None:
                    create_date = create_date.replace(tzinfo=timezone.utc)
                
                age = (datetime.now(timezone.utc) - create_date).days
                is_old = age > DAYS_LIMIT
                
                keys.append(AccessKey(
                    access_key_id=k['AccessKeyId'],
                    age_days=age,
                    status=k['Status'],
                    is_old=is_old
                ))
        except ClientError as e:
            logger.error(f"Error checking keys for {username}: {e}")
        return keys

    def check_admin_access(self, username: str) -> tuple[bool, bool]:
        """
        Checks for AdministratorAccess in:
        1. Attached Managed Policies (User & Groups)
        2. Inline Policies (User & Groups) - looking for Action:* Resource:*
        Returns: (is_managed_admin, is_inline_admin)
        """
        is_managed = False
        is_inline = False

        try:
            # 1. Managed Policies (Direct)
            attached = self._get_api_call(self.iam.list_attached_user_policies, UserName=username)
            for p in attached['AttachedPolicies']:
                if p['PolicyName'] == 'AdministratorAccess':
                    is_managed = True

            # 2. Managed Policies (Groups)
            groups = self._get_api_call(self.iam.list_groups_for_user, UserName=username)
            for group in groups['Groups']:
                g_attached = self._get_api_call(self.iam.list_attached_group_policies, GroupName=group['GroupName'])
                for p in g_attached['AttachedPolicies']:
                    if p['PolicyName'] == 'AdministratorAccess':
                        is_managed = True
                
                # Inline Group Policies
                g_inline = self._get_api_call(self.iam.list_group_policies, GroupName=group['GroupName'])
                for p_name in g_inline['PolicyNames']:
                    if self._check_inline_policy_doc(group['GroupName'], p_name, is_group=True):
                        is_inline = True

            # 3. Inline Policies (Direct)
            u_inline = self._get_api_call(self.iam.list_user_policies, UserName=username)
            for p_name in u_inline['PolicyNames']:
                if self._check_inline_policy_doc(username, p_name, is_group=False):
                    is_inline = True

        except ClientError as e:
            logger.error(f"Error checking admin access for {username}: {e}")
        
        return is_managed, is_inline

    def _check_inline_policy_doc(self, entity_name: str, policy_name: str, is_group: bool) -> bool:
        """Helper to fetch and parse inline policy document."""
        try:
            if is_group:
                resp = self._get_api_call(self.iam.get_group_policy, GroupName=entity_name, PolicyName=policy_name)
            else:
                resp = self._get_api_call(self.iam.get_user_policy, UserName=entity_name, PolicyName=policy_name)
            
            doc = resp['PolicyDocument']
            for statement in doc.get('Statement', []):
                if statement.get('Effect') == 'Allow':
                    actions = statement.get('Action')
                    resources = statement.get('Resource')
                    
                    # Normalize to list
                    if isinstance(actions, str): actions = [actions]
                    if isinstance(resources, str): resources = [resources]
                    
                    if '*' in actions and '*' in resources:
                        return True
        except Exception as e:
            logger.warning(f"Failed to parse inline policy {policy_name} for {entity_name}: {e}")
        return False

    def audit_single_user(self, username: str) -> UserAudit:
        """Worker function to audit a single user."""
        try:
            mfa = self.check_mfa(username)
            keys = self.check_keys(username)
            is_managed_admin, is_inline_admin = self.check_admin_access(username)
            
            return UserAudit(
                username=username,
                mfa_enabled=mfa,
                keys=keys,
                is_admin=is_managed_admin,
                has_inline_admin=is_inline_admin
            )
        except Exception as e:
            logger.error(f"Fatal error auditing {username}: {e}")
            return UserAudit(
                username=username, 
                mfa_enabled=False, 
                is_admin=False, 
                error=str(e)
            )

    def run(self) -> List[UserAudit]:
        """Run the full audit concurrently."""
        users = self.get_all_users()
        results = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True
        ) as progress:
            task = progress.add_task(f"Auditing {len(users)} users...", total=len(users))
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_user = {executor.submit(self.audit_single_user, u): u for u in users}
                
                for future in concurrent.futures.as_completed(future_to_user):
                    results.append(future.result())
                    progress.advance(task)
        
        return results


def main():
    console = Console()
    console.print("[bold blue]🚀 Starting Enterprise IAM Audit...[/bold blue]")

    try:
        auditor = IAMAuditor()
        results = auditor.run()

        # Table Output
        table = Table(title="AWS IAM Security Audit")
        table.add_column("User", style="cyan", no_wrap=True)
        table.add_column("MFA", style="magenta")
        table.add_column("Keys", style="green")
        table.add_column("Admin?", style="red")
        table.add_column("Status", style="bold")

        for r in results:
            # MFA
            mfa_str = "✅ ON" if r.mfa_enabled else "❌ OFF"
            
            # Keys
            key_strs = []
            for k in r.keys:
                icon = "⚠️" if k.is_old else "✅"
                key_strs.append(f"{icon} {k.age_days}d")
            keys_display = ", ".join(key_strs) if key_strs else "No Keys"

            # Admin
            admin_str = "No"
            if r.is_admin: admin_str = "🚨 Managed"
            if r.has_inline_admin: admin_str = "🔥 INLINE"
            if r.is_admin and r.has_inline_admin: admin_str = "🚨 BOTH"

            # Status Color
            status_style = "green"
            if r.status in ["ADMIN", "NO_MFA", "OLD_KEYS"]:
                status_style = "yellow"
            if r.status == "ERROR":
                status_style = "red"
            if "INLINE" in admin_str:
                status_style = "red bold blink"

            table.add_row(
                r.username,
                mfa_str,
                keys_display,
                admin_str,
                f"[{status_style}]{r.status}[/{status_style}]"
            )

        console.print(table)
        console.print(f"\n[bold]Audit Complete.[/bold] Scanned {len(results)} users.")

    except Exception as e:
        console.print(f"[bold red]Fatal Error:[/bold red] {e}")


# --- CLI / Main Block ---
if __name__ == "__main__":
    main()
