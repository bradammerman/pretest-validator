"""
Utility Functions for Pretest Validator
=======================================

This module provides common utility functions used across validators,
including network connectivity tests, DNS resolution, and result types.

Core Types:
-----------
- ValidationStatus: Enum of possible check outcomes (SUCCESS, FAILURE, etc.)
- ValidationResult: Dataclass holding the result of a single validation check

Network Utilities:
------------------
- ping_host(): ICMP ping test with latency measurement
- resolve_dns(): DNS record resolution
- check_port(): TCP port connectivity test
- get_public_ip(): Retrieve current public IP address

Usage:
------
    from pretest_validator.utils import ping_host, ValidationResult, ValidationStatus
    
    success, latency = ping_host('192.168.1.1', timeout=5)
    if success:
        result = ValidationResult(
            name="Ping Test",
            status=ValidationStatus.SUCCESS,
            message=f"Host reachable, latency: {latency}ms"
        )

Requirements:
-------------
    - dnspython>=2.3 (for DNS resolution)
    - requests>=2.28 (for public IP lookup)
"""

import subprocess
import platform
import socket
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class ValidationStatus(Enum):
    """
    Possible outcomes for a validation check.
    
    Used to categorize results for reporting and exit code determination.
    
    Values:
        SUCCESS: Check passed completely
        FAILURE: Check failed (will cause non-zero exit code)
        WARNING: Check completed with concerns (does not fail the run)
        SKIPPED: Check was skipped (not configured or disabled)
        ERROR: Check encountered an unexpected error
    """
    SUCCESS = "success"
    FAILURE = "failure"
    WARNING = "warning"
    SKIPPED = "skipped"
    ERROR = "error"


@dataclass
class ValidationResult:
    """
    Result of a single validation check.
    
    This dataclass captures the outcome of one validation test, including
    its status, a human-readable message, and optional detailed data.
    
    Attributes:
        name: Short identifier for the check (e.g., "DNS: example.com")
        status: ValidationStatus enum indicating pass/fail/warning
        message: Human-readable description of the result
        details: Optional dict with additional data (IPs, timing, etc.)
    
    Example:
        result = ValidationResult(
            name="DNS: example.com",
            status=ValidationStatus.SUCCESS,
            message="Resolved to 93.184.216.34",
            details={'ips': ['93.184.216.34']}
        )
    """
    name: str
    status: ValidationStatus
    message: str
    details: Optional[dict] = None
    
    def is_success(self) -> bool:
        """Check if this result indicates success."""
        return self.status == ValidationStatus.SUCCESS
    
    def is_failure(self) -> bool:
        """Check if this result indicates failure (FAILURE or ERROR)."""
        return self.status in (ValidationStatus.FAILURE, ValidationStatus.ERROR)


def ping_host(host: str, timeout: int = 5) -> tuple[bool, Optional[float]]:
    """
    Ping a host using system ping command.
    
    Performs an ICMP ping test to check if a host is reachable. Works
    on macOS, Linux, and Windows by adapting command flags.
    
    Args:
        host: Hostname or IP address to ping
        timeout: Maximum seconds to wait for response
    
    Returns:
        Tuple of (success: bool, latency_ms: float or None)
        - success is True if ping received a response
        - latency_ms is the round-trip time if available
    
    Example:
        success, latency = ping_host('192.168.1.1', timeout=5)
        if success:
            print(f"Host reachable, latency: {latency}ms")
        else:
            print("Host unreachable")
    
    Note:
        ICMP may be blocked by firewalls. A failed ping doesn't
        necessarily mean the host is down - it may just filter ICMP.
    """
    # Determine OS-specific ping flags
    # -n (Windows) or -c (Unix): number of packets
    # -w (Windows) or -W (Unix): timeout
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
    
    try:
        result = subprocess.run(
            ['ping', param, '1', timeout_param, str(timeout), host],
            capture_output=True,
            text=True,
            timeout=timeout + 2  # Allow extra time for subprocess overhead
        )
        
        if result.returncode == 0:
            # Parse latency from ping output
            output = result.stdout
            latency = None
            
            # Look for "time=X.Xms" pattern in output
            if 'time=' in output:
                try:
                    time_part = output.split('time=')[1]
                    latency = float(time_part.split()[0].replace('ms', ''))
                except (IndexError, ValueError):
                    pass
            
            return True, latency
        return False, None
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
        return False, None


def resolve_dns(hostname: str, record_type: str = 'A') -> tuple[bool, list[str]]:
    """
    Resolve DNS records for a hostname.
    
    Performs DNS lookup using dnspython library for reliable resolution.
    
    Args:
        hostname: Domain name to resolve
        record_type: DNS record type ('A', 'AAAA', 'MX', 'TXT', etc.)
    
    Returns:
        Tuple of (success: bool, addresses: list[str])
        - success is True if resolution succeeded
        - addresses contains the resolved values
    
    Example:
        success, ips = resolve_dns('example.com', 'A')
        if success:
            print(f"Resolved to: {', '.join(ips)}")
    
    Requirements:
        dnspython>=2.3
    """
    import dns.resolver
    
    try:
        answers = dns.resolver.resolve(hostname, record_type)
        return True, [str(rdata) for rdata in answers]
    except Exception:
        return False, []


def check_port(host: str, port: int, timeout: int = 5) -> bool:
    """
    Check if a TCP port is open on a host.
    
    Attempts to establish a TCP connection to verify the port is
    accepting connections.
    
    Args:
        host: Hostname or IP address
        port: TCP port number to check
        timeout: Connection timeout in seconds
    
    Returns:
        True if port is open and accepting connections, False otherwise
    
    Example:
        if check_port('example.com', 22):
            print("SSH port is open")
        else:
            print("SSH port is closed or filtered")
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except socket.error:
        return False


def get_public_ip() -> Optional[str]:
    """
    Get the current public IP address.
    
    Queries multiple public IP detection services to determine
    the machine's public-facing IP address. Useful for VPN validation.
    
    Returns:
        Public IP address as string, or None if detection failed
    
    Example:
        ip = get_public_ip()
        if ip:
            print(f"Your public IP: {ip}")
        else:
            print("Could not determine public IP")
    
    Note:
        Requires internet access. Tries multiple services for reliability.
    """
    import requests
    
    # List of public IP detection services (try multiple for reliability)
    services = [
        'https://api.ipify.org',
        'https://ifconfig.me/ip',
        'https://icanhazip.com',
    ]
    
    for service in services:
        try:
            response = requests.get(service, timeout=5)
            if response.status_code == 200:
                return response.text.strip()
        except requests.RequestException:
            continue
    
    return None


def format_bytes(size: int) -> str:
    """
    Format byte count to human-readable string.
    
    Args:
        size: Size in bytes
    
    Returns:
        Formatted string (e.g., "1.5 MB", "256 KB")
    
    Example:
        print(format_bytes(1536))  # "1.50 KB"
        print(format_bytes(1048576))  # "1.00 MB"
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} PB"


def truncate_string(s: str, max_length: int = 50) -> str:
    """
    Truncate a string with ellipsis if it exceeds max length.
    
    Args:
        s: String to truncate
        max_length: Maximum allowed length (including ellipsis)
    
    Returns:
        Original string if short enough, or truncated with '...'
    
    Example:
        truncate_string("Hello World", 8)  # "Hello..."
        truncate_string("Hi", 8)  # "Hi"
    """
    if len(s) <= max_length:
        return s
    return s[:max_length - 3] + '...'
