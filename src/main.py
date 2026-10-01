import json
import sys

import click
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """Cloud-IAM-Optimizer: AWS/GCP IAM Least Privilege Auditor."""
    pass


@cli.command()
@click.option(
    "--provider",
    type=click.Choice(["aws", "gcp"]),
    required=True,
    help="Cloud provider to audit.",
)
@click.option(
    "--output",
    type=click.Choice(["json", "text"]),
    default="text",
    help="Output format.",
)
def audit(provider, output):
    """Run an IAM audit for the specified provider."""
    click.echo(
        f"{Fore.CYAN}Starting audit for provider: "
        f"{Style.BRIGHT}{provider}{Style.RESET_ALL}"
    )
    _run_audit_logic(provider, output)


def _run_audit_logic(provider, output):
    """Dispatch audit to the provider implementation."""
    if provider == "gcp":
        click.echo(
            f"{Fore.RED}GCP audit is not implemented yet. "
            f"Only --provider aws is supported.{Style.RESET_ALL}",
            err=True,
        )
        sys.exit(1)

    # AWS path — reuse the real auditor in audit_aws
    from audit_aws import IAMAuditor, main as aws_main

    if output == "json":
        auditor = IAMAuditor()
        results = auditor.run()
        payload = [r.model_dump() for r in results]
        click.echo(json.dumps(payload, default=str, indent=2))
    else:
        aws_main()


if __name__ == "__main__":
    cli()
