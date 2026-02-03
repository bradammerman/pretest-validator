"""
Pretest Validator
=================

A command-line tool for penetration testers to validate engagement prerequisites
before starting a security assessment.

Purpose:
--------
Before a penetration test begins, testers need to verify that all targets are
reachable, credentials work, and configurations are correct. This tool automates
those checks and produces clear reports.

What It Validates:
------------------
- Domain DNS resolution and HTTP/HTTPS connectivity
- CIDR/IP range validity and host reachability
- VPN configuration and internal network connectivity
- API tokens and endpoint accessibility
- SSH credentials (key-based and password authentication)
- Web application login credentials
- MFA configurations (TOTP code generation, backup codes)

Installation:
-------------
    pip install pyyaml requests dnspython rich paramiko

Usage:
------
    # Basic usage
    python -m pretest_validator.cli pretest.yaml

    # Export reports
    python -m pretest_validator.cli pretest.yaml --json report.json --md report.md

    # Run specific validators
    python -m pretest_validator.cli pretest.yaml --only domains --only ssh

Requirements:
-------------
- Python 3.10+
- pyyaml>=6.0
- requests>=2.28
- dnspython>=2.3
- rich>=13.0
- paramiko>=3.0

Example:
--------
    from pretest_validator import load_config, ValidationResult
    
    config = load_config('pretest.yaml')
    print(f"Validating engagement: {config.client} - {config.engagement_id}")
"""

__version__ = '0.1.0'


def __getattr__(name: str):
    """Lazy imports to avoid circular import issues when running as module."""
    if name == 'load_config':
        from .config import load_config
        return load_config
    elif name == 'PretestConfig':
        from .config import PretestConfig
        return PretestConfig
    elif name == 'ValidationResult':
        from .utils import ValidationResult
        return ValidationResult
    elif name == 'ValidationStatus':
        from .utils import ValidationStatus
        return ValidationStatus
    elif name == 'ReportGenerator':
        from .report import ReportGenerator
        return ReportGenerator
    elif name == 'main':
        from .cli import main
        return main
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    '__version__',
    'load_config',
    'PretestConfig',
    'ValidationResult',
    'ValidationStatus',
    'ReportGenerator',
    'main',
]
