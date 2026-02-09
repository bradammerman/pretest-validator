"""
Validators Package for Pretest Validator
========================================

This package contains all validation modules for the pretest-validator tool.
Each validator checks a specific category of engagement prerequisites.

Available Validators:
---------------------
- DomainValidator: DNS resolution, HTTP/HTTPS connectivity
- CIDRValidator: IP range format validation, sample host ping tests
- VPNValidator: Config file verification, public IP check, internal connectivity
- APIValidator: REST API endpoint testing with authentication
- SSHValidator: Port connectivity, key-based and password authentication
- WebLoginValidator: Web application form-based login testing
- MFAValidator: TOTP/HOTP code generation, backup code validation

Usage:
------
    from pretest_validator.validators import DomainValidator
    from pretest_validator.config import DomainConfig
    
    config = DomainConfig(targets=['example.com'], check_dns=True)
    validator = DomainValidator(config)
    results = validator.validate_all()
    
    for result in results:
        print(f"{result.name}: {result.status.value} - {result.message}")

Each validator follows the same pattern:
1. Initialize with its configuration dataclass
2. Call validate_all() to run all checks
3. Returns list of ValidationResult objects
"""

from .domains import DomainValidator
from .cidrs import CIDRValidator
from .vpn import VPNValidator
from .api import APIValidator
from .ssh import SSHValidator
from .web_login import WebLoginValidator
from .mfa import MFAValidator
from .cloud import CloudValidator

__all__ = [
    'DomainValidator',
    'CIDRValidator',
    'VPNValidator',
    'APIValidator',
    'SSHValidator',
    'WebLoginValidator',
    'MFAValidator',
    'CloudValidator',
]
