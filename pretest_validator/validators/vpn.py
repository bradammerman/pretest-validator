"""VPN validation - verify VPN connectivity and configuration."""

import subprocess
import os
from pathlib import Path

from ..utils import ValidationResult, ValidationStatus, get_public_ip, ping_host
from ..config import VPNConfig


class VPNValidator:
    """Validator for VPN connectivity."""
    
    def __init__(self, config: VPNConfig):
        self.config = config
    
    def validate_all(self) -> list[ValidationResult]:
        """Validate VPN configuration and connectivity."""
        results = []
        
        if not self.config.enabled:
            results.append(ValidationResult(
                name="VPN",
                status=ValidationStatus.SKIPPED,
                message="VPN validation not enabled"
            ))
            return results
        
        # Check config file exists
        if self.config.config_file:
            results.append(self._check_config_file())
        
        # Check current public IP
        results.append(self._check_public_ip())
        
        # Check internal connectivity if test_host specified
        if self.config.test_host:
            results.append(self._check_internal_host())
        
        return results
    
    def _check_config_file(self) -> ValidationResult:
        """Verify VPN config file exists and is readable."""
        config_path = Path(self.config.config_file).expanduser()
        
        if not config_path.exists():
            return ValidationResult(
                name="VPN Config File",
                status=ValidationStatus.FAILURE,
                message=f"Config file not found: {self.config.config_file}"
            )
        
        if not config_path.is_file():
            return ValidationResult(
                name="VPN Config File",
                status=ValidationStatus.FAILURE,
                message=f"Path is not a file: {self.config.config_file}"
            )
        
        try:
            # Check if readable
            with open(config_path, 'r') as f:
                content = f.read()
            
            # Basic validation based on VPN type
            if self.config.type.lower() == 'openvpn':
                if 'remote' not in content.lower():
                    return ValidationResult(
                        name="VPN Config File",
                        status=ValidationStatus.WARNING,
                        message="OpenVPN config may be incomplete (no 'remote' directive)"
                    )
            elif self.config.type.lower() == 'wireguard':
                if '[interface]' not in content.lower():
                    return ValidationResult(
                        name="VPN Config File",
                        status=ValidationStatus.WARNING,
                        message="WireGuard config may be incomplete (no [Interface] section)"
                    )
            
            return ValidationResult(
                name="VPN Config File",
                status=ValidationStatus.SUCCESS,
                message=f"Config file exists and is readable ({len(content)} bytes)",
                details={
                    'path': str(config_path),
                    'size': len(content),
                    'type': self.config.type
                }
            )
            
        except PermissionError:
            return ValidationResult(
                name="VPN Config File",
                status=ValidationStatus.FAILURE,
                message=f"Permission denied reading config file"
            )
        except Exception as e:
            return ValidationResult(
                name="VPN Config File",
                status=ValidationStatus.ERROR,
                message=f"Error reading config: {str(e)}"
            )
    
    def _check_public_ip(self) -> ValidationResult:
        """Check current public IP against expected VPN IP."""
        current_ip = get_public_ip()
        
        if not current_ip:
            return ValidationResult(
                name="VPN Public IP",
                status=ValidationStatus.ERROR,
                message="Could not determine current public IP"
            )
        
        if not self.config.expected_ip:
            return ValidationResult(
                name="VPN Public IP",
                status=ValidationStatus.WARNING,
                message=f"Current IP: {current_ip} (no expected IP configured to compare)",
                details={'current_ip': current_ip}
            )
        
        if current_ip == self.config.expected_ip:
            return ValidationResult(
                name="VPN Public IP",
                status=ValidationStatus.SUCCESS,
                message=f"VPN connected - IP matches expected: {current_ip}",
                details={'current_ip': current_ip, 'expected_ip': self.config.expected_ip}
            )
        else:
            return ValidationResult(
                name="VPN Public IP",
                status=ValidationStatus.WARNING,
                message=f"IP mismatch - Current: {current_ip}, Expected: {self.config.expected_ip}",
                details={'current_ip': current_ip, 'expected_ip': self.config.expected_ip}
            )
    
    def _check_internal_host(self) -> ValidationResult:
        """Check connectivity to internal test host."""
        host = self.config.test_host
        
        success, latency = ping_host(host, timeout=5)
        
        if success:
            return ValidationResult(
                name="VPN Internal Host",
                status=ValidationStatus.SUCCESS,
                message=f"Internal host {host} reachable{f' ({latency:.1f}ms)' if latency else ''}",
                details={'host': host, 'latency_ms': latency}
            )
        else:
            return ValidationResult(
                name="VPN Internal Host",
                status=ValidationStatus.FAILURE,
                message=f"Cannot reach internal host {host} - VPN may not be connected",
                details={'host': host}
            )
