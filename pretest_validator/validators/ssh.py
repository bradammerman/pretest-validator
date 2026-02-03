"""SSH validation - verify SSH credentials and connectivity."""

import paramiko
from pathlib import Path
from typing import Optional

from ..utils import ValidationResult, ValidationStatus, check_port
from ..config import SSHConfig


class SSHValidator:
    """Validator for SSH connectivity and credentials."""
    
    def __init__(self, config: SSHConfig):
        self.config = config
    
    def validate_all(self) -> list[ValidationResult]:
        """Validate all configured SSH targets."""
        results = []
        
        if not self.config.targets:
            results.append(ValidationResult(
                name="SSH",
                status=ValidationStatus.SKIPPED,
                message="No SSH targets configured for validation"
            ))
            return results
        
        for target in self.config.targets:
            results.extend(self.validate_ssh(target))
        
        return results
    
    def validate_ssh(self, target: dict) -> list[ValidationResult]:
        """Validate a single SSH target."""
        results = []
        
        host = target.get('host', '')
        port = target.get('port', 22)
        username = target.get('username', '')
        key_file = target.get('key_file')
        password = target.get('password')
        
        name = f"{username}@{host}:{port}" if username else f"{host}:{port}"
        
        if not host:
            results.append(ValidationResult(
                name=f"SSH: {name}",
                status=ValidationStatus.ERROR,
                message="No host specified for SSH target"
            ))
            return results
        
        # Check port is open
        port_result = self._check_port(host, port)
        results.append(port_result)
        
        if port_result.status != ValidationStatus.SUCCESS:
            return results
        
        # If we have credentials, try to authenticate
        if username and (key_file or password):
            results.append(self._check_auth(host, port, username, key_file, password))
        else:
            results.append(ValidationResult(
                name=f"SSH Auth: {name}",
                status=ValidationStatus.SKIPPED,
                message="No credentials provided - skipping authentication test"
            ))
        
        return results
    
    def _check_port(self, host: str, port: int) -> ValidationResult:
        """Check if SSH port is open."""
        name = f"SSH Port: {host}:{port}"
        
        if check_port(host, port, timeout=self.config.timeout):
            return ValidationResult(
                name=name,
                status=ValidationStatus.SUCCESS,
                message=f"Port {port} is open"
            )
        else:
            return ValidationResult(
                name=name,
                status=ValidationStatus.FAILURE,
                message=f"Port {port} is closed or filtered"
            )
    
    def _check_auth(self, host: str, port: int, username: str, 
                    key_file: Optional[str], password: Optional[str]) -> ValidationResult:
        """Test SSH authentication."""
        name = f"SSH Auth: {username}@{host}"
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            if key_file:
                # Key-based authentication
                key_path = Path(key_file).expanduser()
                
                if not key_path.exists():
                    return ValidationResult(
                        name=name,
                        status=ValidationStatus.FAILURE,
                        message=f"Key file not found: {key_file}"
                    )
                
                try:
                    # Try to load the key (supports RSA, DSA, ECDSA, Ed25519)
                    pkey = None
                    key_types = [
                        paramiko.RSAKey,
                        paramiko.DSSKey,
                        paramiko.ECDSAKey,
                        paramiko.Ed25519Key,
                    ]
                    
                    for key_type in key_types:
                        try:
                            pkey = key_type.from_private_key_file(str(key_path))
                            break
                        except paramiko.SSHException:
                            continue
                    
                    if pkey is None:
                        return ValidationResult(
                            name=name,
                            status=ValidationStatus.FAILURE,
                            message="Could not load private key (unsupported format or passphrase required)"
                        )
                    
                    client.connect(
                        host,
                        port=port,
                        username=username,
                        pkey=pkey,
                        timeout=self.config.timeout,
                        look_for_keys=False,
                        allow_agent=False,
                    )
                    
                except paramiko.SSHException as e:
                    return ValidationResult(
                        name=name,
                        status=ValidationStatus.FAILURE,
                        message=f"Key authentication failed: {str(e)}"
                    )
            else:
                # Password authentication
                client.connect(
                    host,
                    port=port,
                    username=username,
                    password=password,
                    timeout=self.config.timeout,
                    look_for_keys=False,
                    allow_agent=False,
                )
            
            # Get server info
            transport = client.get_transport()
            server_banner = transport.remote_version if transport else "Unknown"
            
            client.close()
            
            return ValidationResult(
                name=name,
                status=ValidationStatus.SUCCESS,
                message=f"Authentication successful (Server: {server_banner})",
                details={
                    'host': host,
                    'port': port,
                    'username': username,
                    'auth_method': 'key' if key_file else 'password',
                    'server_version': server_banner,
                }
            )
            
        except paramiko.AuthenticationException:
            return ValidationResult(
                name=name,
                status=ValidationStatus.FAILURE,
                message="Authentication failed - invalid credentials"
            )
        except paramiko.SSHException as e:
            return ValidationResult(
                name=name,
                status=ValidationStatus.ERROR,
                message=f"SSH error: {str(e)}"
            )
        except TimeoutError:
            return ValidationResult(
                name=name,
                status=ValidationStatus.FAILURE,
                message=f"Connection timed out ({self.config.timeout}s)"
            )
        except Exception as e:
            return ValidationResult(
                name=name,
                status=ValidationStatus.ERROR,
                message=f"Connection error: {str(e)}"
            )
        finally:
            client.close()
