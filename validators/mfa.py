"""MFA validation - verify MFA configuration and TOTP secrets."""

import time
import hmac
import hashlib
import struct
import base64
from typing import Optional

from ..utils import ValidationResult, ValidationStatus
from ..config import MFAConfig


class MFAValidator:
    """Validator for Multi-Factor Authentication configurations."""
    
    def __init__(self, config: MFAConfig):
        self.config = config
    
    def validate_all(self) -> list[ValidationResult]:
        """Validate all configured MFA targets."""
        results = []
        
        if not self.config.targets:
            results.append(ValidationResult(
                name="MFA",
                status=ValidationStatus.SKIPPED,
                message="No MFA targets configured for validation"
            ))
            return results
        
        for target in self.config.targets:
            results.append(self.validate_mfa(target))
        
        return results
    
    def validate_mfa(self, target: dict) -> ValidationResult:
        """Validate a single MFA target."""
        name = target.get('name', 'Unnamed MFA')
        mfa_type = target.get('type', '').lower()
        secret = target.get('secret', '')
        description = target.get('description', '')
        
        if mfa_type == 'totp':
            return self._validate_totp(name, secret)
        elif mfa_type == 'hotp':
            counter = target.get('counter', 0)
            return self._validate_hotp(name, secret, counter)
        elif mfa_type in ('sms', 'email', 'push', 'call'):
            return self._validate_oob(name, mfa_type, description)
        elif mfa_type == 'backup_codes':
            codes = target.get('codes', [])
            return self._validate_backup_codes(name, codes)
        else:
            return ValidationResult(
                name=f"MFA: {name}",
                status=ValidationStatus.WARNING,
                message=f"Unknown MFA type '{mfa_type}' - manual verification required",
                details={'type': mfa_type, 'description': description}
            )
    
    def _validate_totp(self, name: str, secret: str) -> ValidationResult:
        """Validate TOTP secret and generate current code."""
        if not secret:
            return ValidationResult(
                name=f"MFA TOTP: {name}",
                status=ValidationStatus.FAILURE,
                message="No TOTP secret provided"
            )
        
        try:
            # Clean and validate the secret
            secret_clean = secret.upper().replace(' ', '').replace('-', '')
            
            # Validate base32 encoding
            try:
                # Add padding if needed (base32 requires length to be multiple of 8)
                padding_needed = (8 - len(secret_clean) % 8) % 8
                secret_bytes = base64.b32decode(secret_clean + '=' * padding_needed)
            except Exception:
                return ValidationResult(
                    name=f"MFA TOTP: {name}",
                    status=ValidationStatus.FAILURE,
                    message="Invalid TOTP secret - not valid base32 encoding"
                )
            
            # Generate current TOTP code
            current_code = self._generate_totp(secret_bytes)
            time_remaining = 30 - (int(time.time()) % 30)
            
            return ValidationResult(
                name=f"MFA TOTP: {name}",
                status=ValidationStatus.SUCCESS,
                message=f"Valid TOTP secret - Current code: {current_code} (expires in {time_remaining}s)",
                details={
                    'current_code': current_code,
                    'time_remaining': time_remaining,
                    'secret_length': len(secret_bytes),
                }
            )
            
        except Exception as e:
            return ValidationResult(
                name=f"MFA TOTP: {name}",
                status=ValidationStatus.ERROR,
                message=f"TOTP validation error: {str(e)}"
            )
    
    def _generate_totp(self, secret_bytes: bytes, time_step: int = 30, digits: int = 6) -> str:
        """Generate a TOTP code."""
        # Get current time counter
        counter = int(time.time()) // time_step
        
        # Pack counter as big-endian 64-bit integer
        counter_bytes = struct.pack('>Q', counter)
        
        # Generate HMAC-SHA1
        hmac_hash = hmac.new(secret_bytes, counter_bytes, hashlib.sha1).digest()
        
        # Dynamic truncation
        offset = hmac_hash[-1] & 0x0F
        binary = struct.unpack('>I', hmac_hash[offset:offset + 4])[0] & 0x7FFFFFFF
        
        # Generate code
        code = binary % (10 ** digits)
        return str(code).zfill(digits)
    
    def _validate_hotp(self, name: str, secret: str, counter: int) -> ValidationResult:
        """Validate HOTP secret and generate code for given counter."""
        if not secret:
            return ValidationResult(
                name=f"MFA HOTP: {name}",
                status=ValidationStatus.FAILURE,
                message="No HOTP secret provided"
            )
        
        try:
            secret_clean = secret.upper().replace(' ', '').replace('-', '')
            padding_needed = (8 - len(secret_clean) % 8) % 8
            secret_bytes = base64.b32decode(secret_clean + '=' * padding_needed)
            
            # Generate HOTP code
            code = self._generate_hotp(secret_bytes, counter)
            
            return ValidationResult(
                name=f"MFA HOTP: {name}",
                status=ValidationStatus.SUCCESS,
                message=f"Valid HOTP secret - Code for counter {counter}: {code}",
                details={
                    'current_code': code,
                    'counter': counter,
                }
            )
            
        except Exception as e:
            return ValidationResult(
                name=f"MFA HOTP: {name}",
                status=ValidationStatus.ERROR,
                message=f"HOTP validation error: {str(e)}"
            )
    
    def _generate_hotp(self, secret_bytes: bytes, counter: int, digits: int = 6) -> str:
        """Generate an HOTP code."""
        counter_bytes = struct.pack('>Q', counter)
        hmac_hash = hmac.new(secret_bytes, counter_bytes, hashlib.sha1).digest()
        offset = hmac_hash[-1] & 0x0F
        binary = struct.unpack('>I', hmac_hash[offset:offset + 4])[0] & 0x7FFFFFFF
        code = binary % (10 ** digits)
        return str(code).zfill(digits)
    
    def _validate_oob(self, name: str, mfa_type: str, description: str) -> ValidationResult:
        """Validate out-of-band MFA (SMS, email, push, call)."""
        return ValidationResult(
            name=f"MFA {mfa_type.upper()}: {name}",
            status=ValidationStatus.WARNING,
            message=f"{mfa_type.upper()} MFA configured - manual verification required",
            details={
                'type': mfa_type,
                'description': description,
                'note': 'Out-of-band MFA cannot be automatically validated',
            }
        )
    
    def _validate_backup_codes(self, name: str, codes: list) -> ValidationResult:
        """Validate backup codes are present."""
        if not codes:
            return ValidationResult(
                name=f"MFA Backup Codes: {name}",
                status=ValidationStatus.WARNING,
                message="No backup codes provided"
            )
        
        return ValidationResult(
            name=f"MFA Backup Codes: {name}",
            status=ValidationStatus.SUCCESS,
            message=f"{len(codes)} backup codes configured",
            details={
                'count': len(codes),
                'note': 'Store backup codes securely',
            }
        )
