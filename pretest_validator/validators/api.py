"""API token validation - verify API credentials and connectivity."""

import requests
from typing import Any

from ..utils import ValidationResult, ValidationStatus, truncate_string
from ..config import APIConfig


class APIValidator:
    """Validator for API tokens and endpoints."""
    
    def __init__(self, config: APIConfig):
        self.config = config
    
    def validate_all(self) -> list[ValidationResult]:
        """Validate all configured API targets."""
        results = []
        
        if not self.config.targets:
            results.append(ValidationResult(
                name="API",
                status=ValidationStatus.SKIPPED,
                message="No API targets configured for validation"
            ))
            return results
        
        for target in self.config.targets:
            results.append(self.validate_api(target))
        
        return results
    
    def validate_api(self, target: dict) -> ValidationResult:
        """Validate a single API target."""
        name = target.get('name', 'Unnamed API')
        url = target.get('url', '')
        method = target.get('method', 'GET').upper()
        headers = target.get('headers', {})
        body = target.get('body')
        expected_status = target.get('expected_status', 200)
        timeout = target.get('timeout', 30)
        verify_ssl = target.get('verify_ssl', True)
        
        if not url:
            return ValidationResult(
                name=f"API: {name}",
                status=ValidationStatus.ERROR,
                message="No URL specified for API target"
            )
        
        try:
            # Build request kwargs
            kwargs: dict[str, Any] = {
                'headers': headers,
                'timeout': timeout,
                'verify': verify_ssl,
            }
            
            if body and method in ('POST', 'PUT', 'PATCH'):
                if isinstance(body, dict):
                    kwargs['json'] = body
                else:
                    kwargs['data'] = body
            
            # Make the request
            response = requests.request(method, url, **kwargs)
            
            # Check status code
            status_ok = False
            if isinstance(expected_status, list):
                status_ok = response.status_code in expected_status
            else:
                status_ok = response.status_code == expected_status
            
            if status_ok:
                return ValidationResult(
                    name=f"API: {name}",
                    status=ValidationStatus.SUCCESS,
                    message=f"{method} {truncate_string(url, 40)} - Status {response.status_code}",
                    details={
                        'url': url,
                        'method': method,
                        'status_code': response.status_code,
                        'response_size': len(response.content),
                        'response_time_ms': response.elapsed.total_seconds() * 1000,
                    }
                )
            else:
                return ValidationResult(
                    name=f"API: {name}",
                    status=ValidationStatus.FAILURE,
                    message=f"Unexpected status {response.status_code} (expected {expected_status})",
                    details={
                        'url': url,
                        'method': method,
                        'status_code': response.status_code,
                        'expected_status': expected_status,
                        'response_preview': truncate_string(response.text, 200),
                    }
                )
                
        except requests.exceptions.SSLError as e:
            return ValidationResult(
                name=f"API: {name}",
                status=ValidationStatus.FAILURE,
                message=f"SSL error: {truncate_string(str(e), 50)}"
            )
        except requests.exceptions.ConnectionError:
            return ValidationResult(
                name=f"API: {name}",
                status=ValidationStatus.FAILURE,
                message=f"Connection failed to {truncate_string(url, 40)}"
            )
        except requests.exceptions.Timeout:
            return ValidationResult(
                name=f"API: {name}",
                status=ValidationStatus.FAILURE,
                message=f"Request timed out ({timeout}s)"
            )
        except requests.exceptions.RequestException as e:
            return ValidationResult(
                name=f"API: {name}",
                status=ValidationStatus.ERROR,
                message=f"Request error: {truncate_string(str(e), 50)}"
            )
