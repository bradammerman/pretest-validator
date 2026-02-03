"""Domain validation - DNS resolution and HTTP/HTTPS reachability."""

import requests
import dns.resolver
from typing import Optional

from ..utils import ValidationResult, ValidationStatus
from ..config import DomainConfig


class DomainValidator:
    """Validator for domain names."""
    
    def __init__(self, config: DomainConfig):
        self.config = config
    
    def validate_all(self) -> list[ValidationResult]:
        """Validate all configured domains."""
        results = []
        
        if not self.config.targets:
            results.append(ValidationResult(
                name="Domains",
                status=ValidationStatus.SKIPPED,
                message="No domains configured for validation"
            ))
            return results
        
        for domain in self.config.targets:
            results.extend(self.validate_domain(domain))
        
        return results
    
    def validate_domain(self, domain: str) -> list[ValidationResult]:
        """Validate a single domain."""
        results = []
        
        # DNS Resolution
        if self.config.check_dns:
            results.append(self._check_dns(domain))
        
        # HTTP Check
        if self.config.check_http:
            results.append(self._check_http(domain))
        
        # HTTPS Check
        if self.config.check_https:
            results.append(self._check_https(domain))
        
        return results
    
    def _check_dns(self, domain: str) -> ValidationResult:
        """Check DNS resolution for a domain."""
        try:
            answers = dns.resolver.resolve(domain, 'A')
            ips = [str(rdata) for rdata in answers]
            
            return ValidationResult(
                name=f"DNS: {domain}",
                status=ValidationStatus.SUCCESS,
                message=f"Resolved to {', '.join(ips)}",
                details={'ips': ips}
            )
        except dns.resolver.NXDOMAIN:
            return ValidationResult(
                name=f"DNS: {domain}",
                status=ValidationStatus.FAILURE,
                message="Domain does not exist (NXDOMAIN)"
            )
        except dns.resolver.NoAnswer:
            return ValidationResult(
                name=f"DNS: {domain}",
                status=ValidationStatus.WARNING,
                message="No A record found"
            )
        except dns.resolver.Timeout:
            return ValidationResult(
                name=f"DNS: {domain}",
                status=ValidationStatus.ERROR,
                message="DNS query timed out"
            )
        except Exception as e:
            return ValidationResult(
                name=f"DNS: {domain}",
                status=ValidationStatus.ERROR,
                message=f"DNS resolution error: {str(e)}"
            )
    
    def _check_http(self, domain: str) -> ValidationResult:
        """Check HTTP connectivity."""
        url = f"http://{domain}"
        return self._check_url(url, "HTTP")
    
    def _check_https(self, domain: str) -> ValidationResult:
        """Check HTTPS connectivity."""
        url = f"https://{domain}"
        return self._check_url(url, "HTTPS")
    
    def _check_url(self, url: str, protocol: str) -> ValidationResult:
        """Check URL reachability."""
        domain = url.split('://')[1].split('/')[0]
        
        try:
            response = requests.get(
                url,
                timeout=self.config.timeout,
                allow_redirects=True,
                verify=True
            )
            
            return ValidationResult(
                name=f"{protocol}: {domain}",
                status=ValidationStatus.SUCCESS,
                message=f"Status {response.status_code}, {len(response.content)} bytes",
                details={
                    'status_code': response.status_code,
                    'content_length': len(response.content),
                    'final_url': response.url
                }
            )
        except requests.exceptions.SSLError as e:
            return ValidationResult(
                name=f"{protocol}: {domain}",
                status=ValidationStatus.WARNING,
                message=f"SSL certificate error: {str(e)[:50]}"
            )
        except requests.exceptions.ConnectionError:
            return ValidationResult(
                name=f"{protocol}: {domain}",
                status=ValidationStatus.FAILURE,
                message="Connection refused or host unreachable"
            )
        except requests.exceptions.Timeout:
            return ValidationResult(
                name=f"{protocol}: {domain}",
                status=ValidationStatus.FAILURE,
                message=f"Request timed out ({self.config.timeout}s)"
            )
        except requests.exceptions.RequestException as e:
            return ValidationResult(
                name=f"{protocol}: {domain}",
                status=ValidationStatus.ERROR,
                message=f"Request error: {str(e)[:50]}"
            )
