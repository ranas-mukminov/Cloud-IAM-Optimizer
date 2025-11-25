import click
import json
import sys
from colorama import init, Fore, Style
from audit_aws import IAMAuditor

# Initialize colorama
init(autoreset=True)

@click.group()
def cli():
    """Cloud-IAM-Optimizer: AWS IAM Security Audit Tool"""
    pass

@cli.command()
@click.option('--profile', default=None, help='AWS CLI profile to use')
@click.option('--output', type=click.Choice(['text', 'json']), default='text', help='Output format')
def audit(profile, output):
    """Run the IAM security audit."""
    click.echo(f"{Fore.CYAN}Starting Cloud-IAM-Optimizer audit...{Style.RESET_ALL}")
    
    try:
        auditor = IAMAuditor(profile_name=profile)
        results = auditor.run_audit()
    except Exception as e:
        click.echo(f"{Fore.RED}Critical Error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

    if output == 'json':
        click.echo(json.dumps(results, indent=2, default=str))
    else:
        print_text_report(results)

def print_text_report(results):
    """Print a pretty text report."""
    click.echo(f"\n{Fore.BLUE}=== Audit Results ==={Style.RESET_ALL}\n")
    
    for user_result in results:
        user = user_result['UserName']
        mfa = user_result['MFA_Enabled']
        old_keys = user_result['Old_Access_Keys']
        is_admin = user_result['Is_Admin']

        # Determine risk level
        risk_color = Fore.GREEN
        if not mfa or old_keys or is_admin:
            risk_color = Fore.RED
        
        click.echo(f"{Fore.WHITE}User: {Style.BRIGHT}{user}{Style.RESET_ALL}")
        
        # MFA Check
        if mfa:
            click.echo(f"  [{Fore.GREEN}PASS{Style.RESET_ALL}] MFA Enabled")
        else:
            click.echo(f"  [{Fore.RED}FAIL{Style.RESET_ALL}] MFA Not Enabled")

        # Admin Check
        if is_admin:
            click.echo(f"  [{Fore.RED}RISK{Style.RESET_ALL}] AdministratorAccess Attached")
        else:
            click.echo(f"  [{Fore.GREEN}PASS{Style.RESET_ALL}] No Admin Access")

        # Key Age Check
        if old_keys:
            click.echo(f"  [{Fore.RED}FAIL{Style.RESET_ALL}] Old Access Keys Found:")
            for key in old_keys:
                click.echo(f"    - {key['AccessKeyId']} ({key['Age']} days old)")
        else:
            click.echo(f"  [{Fore.GREEN}PASS{Style.RESET_ALL}] No Old Access Keys")
        
        click.echo("-" * 40)

    click.echo(f"\n{Fore.CYAN}Powered by Ranas Security Stack (run-as-daemon.dev){Style.RESET_ALL}")

@cli.command()
def version():
    """Show version information."""
    click.echo(f"{Fore.CYAN}Cloud-IAM-Optimizer v1.0.0{Style.RESET_ALL}")
    click.echo("Official Tripwire Tool of Ranas Security Stack")
    click.echo("Visit https://run-as-daemon.dev for commercial support.")

if __name__ == '__main__':
    cli()
