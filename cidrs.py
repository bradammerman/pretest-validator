"""CIDR/IP range validation - verifies IP ranges and tests sample connectivity."""

import ipaddress
import random
from typing import Iterator

from ..utils import ValidationResult, ValidationStatus, ping_host, check_port
from ..config import CIDRConfig


class CIDRValidator:
    """Validator for CIDR ranges."""
    
    def __init__(self, config: CIDRConfig):
        self.config = config
    
    def validate_all(self) -> list[ValidationResult]:
        """Validate all configured CIDR ranges."""
        results = []
        
        if not self.config.targets:
            results.append(ValidationResult(
                name="CIDRs",
                status=ValidationStatus.SKIPPED,
                message="No CIDR ranges configured for validation"
            ))
            return results
        
        for cidr in self.config.targets:
            results.extend(self.validate_cidr(cidr))
        
        return results
    
    def validate_cidr(self, cidr: str) -> list[ValidationResult]:
        """Validate a single CIDR range."""
        results = []
        
        # First, validate the CIDR format
        format_result = self._validate_format(cidr)
        results.append(format_result)
        
        if format_result.status != ValidationStatus.SUCCESS:
            return results
        
        # Get network info
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            results.append(ValidationResult(
                name=f"CIDR Info: {cidr}",
                status=ValidationStatus.SUCCESS,
                message=f"Network: {network.network_address}, Hosts: {network.num_addresses - 2 if network.num_addresses > 2 else network.num_addresses}",
                details={
                    'network_address': str(network.network_address),
                    'broadcast_address': str(network.broadcast_address) if network.num_addresses > 1 else None,
                    'num_hosts': network.num_addresses - 2 if network.num_addresses > 2 else network.num_addresses,
                    'netmask': str(network.netmask),
                }
            ))
            
            # Sample ping test
            results.extend(self._ping_sample(network))
            
        except ValueError as e:
            results.append(ValidationResult(
                name=f"CIDR Info: {cidr}",
                status=ValidationStatus.ERROR,
                message=f"Failed to parse network: {str(e)}"
            ))
        
        return results
    
    def _validate_format(self, cidr: str) -> ValidationResult:
        """Validate CIDR format."""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            return ValidationResult(
                name=f"CIDR Format: {cidr}",
                status=ValidationStatus.SUCCESS,
                message=f"Valid {'IPv4' if network.version == 4 else 'IPv6'} network"
            )
        except ValueError as e:
            return ValidationResult(
                name=f"CIDR Format: {cidr}",
                status=ValidationStatus.FAILURE,
                message=f"Invalid CIDR format: {str(e)}"
            )
    
    def _ping_sample(self, network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> list[ValidationResult]:
        """Ping a sample of hosts from the network."""
        results = []
        
        # Get list of usable hosts
        if network.num_addresses <= 2:
            hosts = list(network.hosts()) or [network.network_address]
        else:
            hosts = list(network.hosts())
        
        if not hosts:
            results.append(ValidationResult(
                name=f"Ping Sample: {network}",
                status=ValidationStatus.SKIPPED,
                message="No usable hosts in network"
            ))
            return results
        
        # Sample hosts to ping
        sample_size = min(self.config.ping_sample, len(hosts))
        if len(hosts) <= sample_size:
            sample_hosts = hosts
        else:
            # Sample from beginning, middle, and end
            sample_hosts = []
            sample_hosts.append(hosts[0])  # First host
            if sample_size > 1:
                sample_hosts.append(hosts[-1])  # Last host
            if sample_size > 2:
                sample_hosts.append(hosts[len(hosts) // 2])  # Middle host
            # Add random hosts if we need more
            remaining = [h for h in hosts if h not in sample_hosts]
            while len(sample_hosts) < sample_size and remaining:
                h = random.choice(remaining)
                remaining.remove(h)
                sample_hosts.append(h)
        
        # Ping each sampled host
        reachable = 0
        for host in sample_hosts:
            success, latency = ping_host(str(host), self.config.timeout)
            if success:
                reachable += 1
                results.append(ValidationResult(
                    name=f"Ping: {host}",
                    status=ValidationStatus.SUCCESS,
                    message=f"Reachable{f', latency: {latency:.1f}ms' if latency else ''}",
                    details={'latency_ms': latency}
                ))
            else:
                results.append(ValidationResult(
                    name=f"Ping: {host}",
                    status=ValidationStatus.WARNING,
                    message="Host unreachable (may be filtered)"
                ))
        
        # Summary
        results.append(ValidationResult(
            name=f"Ping Summary: {network}",
            status=ValidationStatus.SUCCESS if reachable > 0 else ValidationStatus.WARNING,
            message=f"{reachable}/{len(sample_hosts)} sampled hosts reachable",
            details={'reachable': reachable, 'sampled': len(sample_hosts)}
        ))
        
        return results
