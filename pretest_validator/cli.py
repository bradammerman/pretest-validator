"""
Command-Line Interface for Pretest Validator
============================================

This module provides the CLI entry point for the pretest validator tool.
It handles argument parsing, orchestrates validators, and generates reports.

Usage Examples:
---------------
    # Run all validators
    python -m pretest_validator.cli pretest.yaml

    # Export to JSON and Markdown
    python -m pretest_validator.cli pretest.yaml --json report.json --md report.md

    # Run only specific validators
    python -m pretest_validator.cli pretest.yaml --only domains --only cidrs

    # Skip certain validators
    python -m pretest_validator.cli pretest.yaml --skip vpn --skip mfa

    # Quiet mode for CI/CD (only file output)
    python -m pretest_validator.cli pretest.yaml --quiet --json results.json

Exit Codes:
-----------
    0 - All checks passed (or only warnings)
    1 - One or more checks failed or errored

Requirements:
-------------
    - Python 3.10+
    - pyyaml, requests, dnspython, rich, paramiko
"""

import argparse
import sys
import subprocess
from pathlib import Path


# =============================================================================
# DEPENDENCY MANAGEMENT
# =============================================================================

# Required packages with their import names and pip package names
REQUIRED_PACKAGES = [
    ('yaml', 'pyyaml'),           # YAML parsing
    ('requests', 'requests'),      # HTTP requests
    ('dns.resolver', 'dnspython'), # DNS resolution
    ('rich', 'rich'),              # Console formatting
    ('paramiko', 'paramiko'),      # SSH connectivity
    ('bs4', 'beautifulsoup4'),     # HTML parsing for web login
]


def check_dependencies() -> list[tuple[str, str]]:
    """
    Check which required packages are missing.
    
    Returns:
        List of tuples (import_name, pip_name) for missing packages
    """
    missing = []
    
    for import_name, pip_name in REQUIRED_PACKAGES:
        try:
            __import__(import_name.split('.')[0])
        except ImportError:
            missing.append((import_name, pip_name))
    
    return missing


def prompt_install_dependencies(missing: list[tuple[str, str]]) -> bool:
    """
    Prompt user to install missing dependencies.
    
    Args:
        missing: List of (import_name, pip_name) tuples
    
    Returns:
        True if installation succeeded, False otherwise
    """
    pip_packages = [pip_name for _, pip_name in missing]
    
    print("\n" + "=" * 60)
    print("MISSING DEPENDENCIES DETECTED")
    print("=" * 60)
    print("\nThe following packages are required but not installed:\n")
    
    for import_name, pip_name in missing:
        print(f"  - {pip_name}")
    
    print(f"\nInstall command: pip install {' '.join(pip_packages)}")
    print()
    
    # Prompt user
    while True:
        response = input("Would you like to install them now? [Y/n]: ").strip().lower()
        
        if response in ('', 'y', 'yes'):
            return install_dependencies(pip_packages)
        elif response in ('n', 'no'):
            print("\nInstallation cancelled. Please install manually:")
            print(f"  pip install {' '.join(pip_packages)}")
            return False
        else:
            print("Please enter 'y' for yes or 'n' for no.")


def install_dependencies(packages: list[str]) -> bool:
    """
    Install packages using pip.
    
    Args:
        packages: List of pip package names to install
    
    Returns:
        True if installation succeeded, False otherwise
    """
    print(f"\nInstalling: {', '.join(packages)}...")
    print("-" * 40)
    
    try:
        # Run pip install
        result = subprocess.run(
            [sys.executable, '-m', 'pip', 'install'] + packages,
            capture_output=False,  # Show output to user
            text=True,
        )
        
        if result.returncode == 0:
            print("-" * 40)
            print("Installation successful!")
            print()
            return True
        else:
            print("-" * 40)
            print("Installation failed. Please install manually:")
            print(f"  pip install {' '.join(packages)}")
            return False
            
    except Exception as e:
        print(f"\nError during installation: {e}")
        print("Please install manually:")
        print(f"  pip install {' '.join(packages)}")
        return False


def ensure_dependencies() -> bool:
    """
    Ensure all dependencies are installed, prompting to install if needed.
    
    Returns:
        True if all dependencies are available, False otherwise
    """
    missing = check_dependencies()
    
    if not missing:
        # All dependencies installed
        return True
    
    # Prompt to install missing packages
    if prompt_install_dependencies(missing):
        # Verify installation worked
        still_missing = check_dependencies()
        if still_missing:
            print("\nSome packages still missing after installation.")
            print("Please try installing manually and run again.")
            return False
        return True
    
    return False


# =============================================================================
# MAIN CLI LOGIC
# =============================================================================

def create_parser() -> argparse.ArgumentParser:
    """
    Create and configure the argument parser.
    
    Returns:
        Configured ArgumentParser instance with all CLI options.
    """
    # Import here after dependency check
    from . import __version__
    
    parser = argparse.ArgumentParser(
        prog='pretest-validator',
        description='Validate pretest configurations for penetration testing engagements',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic validation
  pretest-validator pretest.yaml

  # Export reports
  pretest-validator pretest.yaml --json report.json
  pretest-validator pretest.yaml --markdown report.md

  # Selective validation
  pretest-validator pretest.yaml --only domains --only cidrs
  pretest-validator pretest.yaml --skip vpn --skip ssh

  # CI/CD integration (quiet mode, check exit code)
  pretest-validator pretest.yaml --quiet --json results.json && echo "All passed"
        """
    )
    
    # Positional argument: config file path
    parser.add_argument(
        'config',
        type=str,
        nargs='?',  # Make optional to allow --version without config
        help='Path to YAML configuration file (e.g., pretest.yaml)',
    )
    
    # Version flag
    parser.add_argument(
        '-v', '--version',
        action='version',
        version=f'%(prog)s {__version__}',
    )
    
    # Report export options
    parser.add_argument(
        '--json',
        type=str,
        metavar='FILE',
        help='Export results to JSON file (machine-readable)',
    )
    
    parser.add_argument(
        '--markdown', '--md',
        type=str,
        metavar='FILE',
        help='Export results to Markdown file (human-readable report)',
    )
    
    # Validator selection options
    parser.add_argument(
        '--skip',
        type=str,
        action='append',
        choices=['domains', 'cidrs', 'vpn', 'api', 'ssh', 'web_login', 'mfa', 'cloud'],
        default=[],
        help='Skip specific validators (can be repeated: --skip vpn --skip mfa)',
    )
    
    parser.add_argument(
        '--only',
        type=str,
        action='append',
        choices=['domains', 'cidrs', 'vpn', 'api', 'ssh', 'web_login', 'mfa', 'cloud'],
        default=[],
        help='Run only specific validators (can be repeated: --only domains --only ssh)',
    )
    
    # Output control options
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Suppress console output (use with --json or --markdown for file-only output)',
    )
    
    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output (useful for logging or piping)',
    )
    
    # Dependency management
    parser.add_argument(
        '--check-deps',
        action='store_true',
        help='Check if all dependencies are installed and exit',
    )
    
    return parser


def run_validators(config, skip: list[str], only: list[str]) -> list:
    """
    Execute all enabled validators and collect their results.
    
    This function instantiates each validator with its configuration section
    and runs validation checks. Validators are run in a logical order:
    network reachability first (domains, cidrs, vpn), then credentials
    (api, ssh, web_login, mfa).
    
    Args:
        config: Loaded PretestConfig with all engagement settings
        skip: List of validator names to skip
        only: List of validator names to exclusively run (if non-empty)
    
    Returns:
        List of ValidationResult objects from all executed validators
    """
    # Import validators here after dependency check
    from .validators import (
        DomainValidator,
        CIDRValidator,
        VPNValidator,
        APIValidator,
        SSHValidator,
        WebLoginValidator,
        MFAValidator,
        CloudValidator,
    )
    
    results = []
    
    # Define available validators in execution order
    all_validators = ['domains', 'cidrs', 'vpn', 'api', 'ssh', 'web_login', 'mfa', 'cloud']
    
    # Determine which validators to run based on --only and --skip flags
    if only:
        # If --only specified, run only those validators
        validators_to_run = [v for v in all_validators if v in only]
    else:
        # Otherwise, run all except skipped ones
        validators_to_run = [v for v in all_validators if v not in skip]
    
    # Execute each enabled validator
    # Domain validation - DNS and HTTP/HTTPS checks
    if 'domains' in validators_to_run:
        validator = DomainValidator(config.domains)
        results.extend(validator.validate_all())
    
    # CIDR validation - IP range format and ping tests
    if 'cidrs' in validators_to_run:
        validator = CIDRValidator(config.cidrs)
        results.extend(validator.validate_all())
    
    # VPN validation - config file, public IP, internal connectivity
    if 'vpn' in validators_to_run:
        validator = VPNValidator(config.vpn)
        results.extend(validator.validate_all())
    
    # API validation - endpoint connectivity and authentication
    if 'api' in validators_to_run:
        validator = APIValidator(config.api)
        results.extend(validator.validate_all())
    
    # SSH validation - port checks and credential testing
    if 'ssh' in validators_to_run:
        validator = SSHValidator(config.ssh)
        results.extend(validator.validate_all())
    
    # Web login validation - form-based authentication
    if 'web_login' in validators_to_run:
        validator = WebLoginValidator(config.web_login)
        results.extend(validator.validate_all())
    
    # MFA validation - TOTP secrets and backup codes
    if 'mfa' in validators_to_run:
        validator = MFAValidator(config.mfa)
        results.extend(validator.validate_all())
    
    # Cloud validation - AWS, Azure, GCP credentials
    if 'cloud' in validators_to_run:
        validator = CloudValidator(config.cloud)
        results.extend(validator.validate_all())
    
    return results


def main(argv: list[str] | None = None) -> int:
    """
    Main entry point for the pretest-validator CLI.
    
    This function:
    1. Checks for required dependencies (prompts to install if missing)
    2. Parses command-line arguments
    3. Loads the YAML configuration file
    4. Runs selected validators
    5. Displays results to console (unless --quiet)
    6. Exports reports if requested (--json, --markdown)
    7. Returns appropriate exit code
    
    Args:
        argv: Command-line arguments (defaults to sys.argv if None)
    
    Returns:
        Exit code: 0 for success/warnings, 1 for failures/errors
    
    Example:
        # Run from command line
        python -m pretest_validator.cli pretest.yaml
        
        # Run programmatically
        from pretest_validator.cli import main
        exit_code = main(['pretest.yaml', '--json', 'report.json'])
    """
    # -------------------------------------------------------------------------
    # Step 1: Check dependencies BEFORE importing anything else
    # -------------------------------------------------------------------------
    if not ensure_dependencies():
        return 1
    
    # Now safe to import modules that require dependencies
    from rich.console import Console
    from .config import load_config
    from .report import ReportGenerator
    
    # -------------------------------------------------------------------------
    # Step 2: Parse arguments
    # -------------------------------------------------------------------------
    parser = create_parser()
    args = parser.parse_args(argv)
    
    # Handle --check-deps flag
    if args.check_deps:
        print("All dependencies are installed!")
        return 0
    
    # Require config file for normal operation
    if not args.config:
        parser.print_help()
        print("\nError: Config file is required.")
        print("Usage: python -m pretest_validator.cli pretest.yaml")
        return 1
    
    # Configure console output
    console = Console(force_terminal=not args.no_color, no_color=args.no_color)
    
    # -------------------------------------------------------------------------
    # Step 3: Load configuration
    # -------------------------------------------------------------------------
    config_path = Path(args.config)
    if not config_path.exists():
        console.print(f"[red]Error: Configuration file not found: {config_path}[/red]")
        return 1
    
    try:
        config = load_config(config_path)
    except Exception as e:
        console.print(f"[red]Error loading configuration: {e}[/red]")
        return 1
    
    # -------------------------------------------------------------------------
    # Step 4: Run validators
    # -------------------------------------------------------------------------
    if not args.quiet:
        console.print(f"[blue]Loading configuration from: {config_path}[/blue]")
        console.print(f"[blue]Running pretest validation for {config.client}...[/blue]")
    
    results = run_validators(config, args.skip, args.only)
    
    # -------------------------------------------------------------------------
    # Step 5: Generate and display report
    # -------------------------------------------------------------------------
    report = ReportGenerator(config, results)
    
    # Display console output (unless quiet mode)
    if not args.quiet:
        report.print_summary()
    
    # Export to JSON if requested
    if args.json:
        report.export_json(args.json)
    
    # Export to Markdown if requested
    if args.markdown:
        report.export_markdown(args.markdown)
    
    # Return exit code based on results
    return report.get_exit_code()


# Allow running as: python -m pretest_validator.cli
if __name__ == '__main__':
    sys.exit(main())
