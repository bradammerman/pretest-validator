"""
Configuration Loader for Pretest Validator
==========================================

This module handles loading and parsing YAML configuration files into
structured dataclasses for use by the validators.

Configuration File Format:
--------------------------
The YAML config file contains sections for each validator type.
All sections are optional - only include what you need to validate.

Example config structure:
    client: ACME Corp
    engagement_id: ACME-2026-01
    
    domains:
      targets:
        - example.com
      check_dns: true
      check_http: true
      check_https: true
    
    cidrs:
      targets:
        - 192.168.1.0/24
      ping_sample: 3
    
    # ... additional sections ...

Usage:
------
    from pretest_validator.config import load_config
    
    config = load_config('pretest.yaml')
    print(f"Client: {config.client}")
    print(f"Domains to test: {config.domains.targets}")

Requirements:
-------------
    - pyyaml>=6.0
"""

import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DomainConfig:
    """
    Configuration for domain validation.
    
    Attributes:
        targets: List of domain names to validate (e.g., ['example.com', 'api.example.com'])
        check_dns: Whether to perform DNS A record resolution
        check_http: Whether to test HTTP (port 80) connectivity
        check_https: Whether to test HTTPS (port 443) connectivity
        timeout: Request timeout in seconds
    """
    targets: list[str] = field(default_factory=list)
    check_dns: bool = True
    check_http: bool = True
    check_https: bool = True
    timeout: int = 10


@dataclass
class CIDRConfig:
    """
    Configuration for CIDR/IP range validation.
    
    Attributes:
        targets: List of CIDR ranges to validate (e.g., ['192.168.1.0/24', '10.0.0.0/16'])
        ping_sample: Number of hosts to ping from each range (samples first, last, middle)
        timeout: Ping timeout in seconds
    """
    targets: list[str] = field(default_factory=list)
    ping_sample: int = 3
    timeout: int = 5


@dataclass
class VPNConfig:
    """
    Configuration for VPN connectivity validation.
    
    Attributes:
        enabled: Whether to perform VPN validation (set False to skip)
        type: VPN type - 'openvpn', 'wireguard', or 'ipsec'
        config_file: Path to VPN configuration file
        expected_ip: Expected public IP address when VPN is connected
        test_host: Internal host to ping to verify VPN routing works
    """
    enabled: bool = False
    type: str = ""
    config_file: str = ""
    expected_ip: str = ""
    test_host: str = ""


@dataclass
class APIConfig:
    """
    Configuration for API token/endpoint validation.
    
    Attributes:
        targets: List of API target dictionaries, each containing:
            - name: Descriptive name for the API
            - url: Full URL to test
            - method: HTTP method (GET, POST, etc.)
            - headers: Dict of headers including auth tokens
            - body: Request body for POST/PUT (optional)
            - expected_status: Expected HTTP status code (default 200)
            - timeout: Request timeout in seconds
            - verify_ssl: Whether to verify SSL certificates
    """
    targets: list[dict] = field(default_factory=list)


@dataclass
class SSHConfig:
    """
    Configuration for SSH connectivity validation.
    
    Attributes:
        targets: List of SSH target dictionaries, each containing:
            - host: Hostname or IP address
            - port: SSH port (default 22)
            - username: SSH username
            - key_file: Path to private key file (for key auth)
            - password: Password (for password auth)
        timeout: Connection timeout in seconds
    """
    targets: list[dict] = field(default_factory=list)
    timeout: int = 10


@dataclass
class WebLoginConfig:
    """
    Configuration for web application login validation.
    
    Attributes:
        targets: List of web login target dictionaries, each containing:
            - name: Descriptive name for the login
            - url: Login page URL
            - login_url: Form submission URL (if different from url)
            - username: Login username/email
            - password: Login password
            - username_field: Form field name for username (default 'username')
            - password_field: Form field name for password (default 'password')
            - success_indicator: Text that appears on successful login
            - failure_indicator: Text that appears on failed login
            - method: HTTP method for form submission (default 'POST')
            - additional_fields: Extra form fields to submit
    """
    targets: list[dict] = field(default_factory=list)


@dataclass
class MFAConfig:
    """
    Configuration for MFA (Multi-Factor Authentication) validation.
    
    Attributes:
        targets: List of MFA target dictionaries, each containing:
            - name: Descriptive name for the MFA
            - type: MFA type - 'totp', 'hotp', 'sms', 'email', 'push', 'backup_codes'
            - secret: Base32-encoded secret for TOTP/HOTP
            - counter: Counter value for HOTP
            - codes: List of backup codes
            - description: Description for out-of-band MFA types
    """
    targets: list[dict] = field(default_factory=list)


@dataclass
class CloudConfig:
    """
    Configuration for cloud provider credential validation.
    
    Attributes:
        targets: List of cloud target dictionaries, each containing:
            - name: Descriptive name for the cloud account
            - provider: Cloud provider - 'aws', 'azure', or 'gcp'
            
            For AWS:
            - access_key_id: AWS access key ID
            - secret_access_key: AWS secret access key
            - session_token: (optional) AWS session token
            - profile: (optional) AWS profile name
            - region: (optional) AWS region (default: us-east-1)
            
            For Azure:
            - tenant_id: Azure AD tenant ID
            - client_id: Service principal client ID
            - client_secret: Service principal client secret
            - subscription_id: (optional) Target subscription ID
            
            For GCP:
            - service_account_file: Path to service account JSON file
            - project_id: (optional) GCP project ID
    """
    targets: list[dict] = field(default_factory=list)


@dataclass
class PretestConfig:
    """
    Main configuration container holding all validator configurations.
    
    This is the top-level dataclass returned by load_config() containing
    engagement metadata and all validator-specific configuration sections.
    
    Attributes:
        client: Client name for the engagement
        engagement_id: Unique identifier for the engagement
        domains: Domain validation configuration
        cidrs: CIDR validation configuration
        vpn: VPN validation configuration
        api: API validation configuration
        ssh: SSH validation configuration
        web_login: Web login validation configuration
        mfa: MFA validation configuration
        cloud: Cloud provider validation configuration
    """
    client: str = ""
    engagement_id: str = ""
    domains: DomainConfig = field(default_factory=DomainConfig)
    cidrs: CIDRConfig = field(default_factory=CIDRConfig)
    vpn: VPNConfig = field(default_factory=VPNConfig)
    api: APIConfig = field(default_factory=APIConfig)
    ssh: SSHConfig = field(default_factory=SSHConfig)
    web_login: WebLoginConfig = field(default_factory=WebLoginConfig)
    mfa: MFAConfig = field(default_factory=MFAConfig)
    cloud: CloudConfig = field(default_factory=CloudConfig)


def load_config(config_path: str | Path) -> PretestConfig:
    """
    Load and parse a YAML configuration file.
    
    This function reads a YAML file and converts it into a structured
    PretestConfig dataclass with all validator configurations.
    
    Args:
        config_path: Path to the YAML configuration file
    
    Returns:
        PretestConfig object with all loaded settings
    
    Raises:
        FileNotFoundError: If the configuration file doesn't exist
        yaml.YAMLError: If the YAML is malformed
    
    Example:
        config = load_config('pretest.yaml')
        print(f"Testing {len(config.domains.targets)} domains")
        for domain in config.domains.targets:
            print(f"  - {domain}")
    """
    config_path = Path(config_path)
    
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    # Load raw YAML data
    with open(config_path, 'r') as f:
        raw = yaml.safe_load(f) or {}
    
    # Create config with engagement metadata
    config = PretestConfig(
        client=raw.get('client', ''),
        engagement_id=raw.get('engagement_id', ''),
    )
    
    # Parse domains section
    if 'domains' in raw:
        d = raw['domains']
        config.domains = DomainConfig(
            targets=d.get('targets', []),
            check_dns=d.get('check_dns', True),
            check_http=d.get('check_http', True),
            check_https=d.get('check_https', True),
            timeout=d.get('timeout', 10),
        )
    
    # Parse CIDRs section
    if 'cidrs' in raw:
        c = raw['cidrs']
        config.cidrs = CIDRConfig(
            targets=c.get('targets', []),
            ping_sample=c.get('ping_sample', 3),
            timeout=c.get('timeout', 5),
        )
    
    # Parse VPN section
    if 'vpn' in raw:
        v = raw['vpn']
        config.vpn = VPNConfig(
            enabled=v.get('enabled', False),
            type=v.get('type', ''),
            config_file=v.get('config_file', ''),
            expected_ip=v.get('expected_ip', ''),
            test_host=v.get('test_host', ''),
        )
    
    # Parse API section
    if 'api' in raw:
        a = raw['api']
        config.api = APIConfig(
            targets=a.get('targets', []),
        )
    
    # Parse SSH section
    if 'ssh' in raw:
        s = raw['ssh']
        config.ssh = SSHConfig(
            targets=s.get('targets', []),
            timeout=s.get('timeout', 10),
        )
    
    # Parse web_login section
    if 'web_login' in raw:
        w = raw['web_login']
        config.web_login = WebLoginConfig(
            targets=w.get('targets', []),
        )
    
    # Parse MFA section
    if 'mfa' in raw:
        m = raw['mfa']
        config.mfa = MFAConfig(
            targets=m.get('targets', []),
        )
    
    # Parse Cloud section
    if 'cloud' in raw:
        c = raw['cloud']
        config.cloud = CloudConfig(
            targets=c.get('targets', []),
        )
    
    return config
