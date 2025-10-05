#!/usr/bin/env python3
"""
LinkShield Backend IP Utilities

Secure client IP detection utilities with proxy validation to prevent IP spoofing.
Implements REQ-008 requirements for trusted proxy validation and secure IP detection.
"""

import ipaddress
import re
from typing import List, Optional, Set, Union
from fastapi import Request
from loguru import logger

from src.config.settings import get_settings

settings = get_settings()


class IPValidator:
    """
    IP validation and extraction utility with proxy validation.
    Prevents IP spoofing by validating proxy headers against trusted proxy networks.
    """
    
    def __init__(self):
        """Initialize IP validator with trusted proxy networks."""
        # Default trusted proxy networks (common load balancers and CDNs)
        self.default_trusted_networks = [
            # Private networks (RFC 1918)
            "10.0.0.0/8",
            "172.16.0.0/12", 
            "192.168.0.0/16",
            # Loopback
            "127.0.0.0/8",
            "::1/128",
            # Link-local
            "169.254.0.0/16",
            "fe80::/10",
            # Common cloud provider networks
            "100.64.0.0/10",  # Carrier-grade NAT
        ]
        
        # Parse trusted networks from settings or use defaults
        self.trusted_networks = self._parse_trusted_networks()
        
        # Compile regex for IP validation
        self.ipv4_pattern = re.compile(
            r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        )
        self.ipv6_pattern = re.compile(
            r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|'
            r'^::1$|^::$|^(?:[0-9a-fA-F]{1,4}:)*::[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*$'
        )
    
    def _parse_trusted_networks(self) -> List[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        """
        Parse trusted proxy networks from settings.
        
        Returns:
            List of trusted network objects
        """
        networks = []
        
        # Get trusted networks from settings if available
        trusted_networks_config = getattr(settings, 'TRUSTED_PROXY_NETWORKS', self.default_trusted_networks)
        
        for network_str in trusted_networks_config:
            try:
                # Handle both IPv4 and IPv6 networks
                network = ipaddress.ip_network(network_str, strict=False)
                networks.append(network)
            except ValueError as e:
                logger.warning(f"Invalid trusted network configuration: {network_str} - {e}")
                continue
        
        # If no valid networks found, use defaults
        if not networks:
            for network_str in self.default_trusted_networks:
                try:
                    network = ipaddress.ip_network(network_str, strict=False)
                    networks.append(network)
                except ValueError:
                    continue
        
        logger.info(f"Loaded {len(networks)} trusted proxy networks")
        return networks
    
    def is_valid_ip(self, ip_str: str) -> bool:
        """
        Validate if string is a valid IP address.
        
        Args:
            ip_str: IP address string to validate
            
        Returns:
            True if valid IP address, False otherwise
        """
        if not ip_str or not isinstance(ip_str, str):
            return False
        
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False
    
    def is_trusted_proxy(self, proxy_ip: str) -> bool:
        """
        Check if IP address is from a trusted proxy network.
        
        Args:
            proxy_ip: IP address of the proxy to validate
            
        Returns:
            True if proxy is trusted, False otherwise
        """
        if not self.is_valid_ip(proxy_ip):
            return False
        
        try:
            ip_addr = ipaddress.ip_address(proxy_ip)
            
            # Check against all trusted networks
            for network in self.trusted_networks:
                if ip_addr in network:
                    return True
            
            return False
        except ValueError:
            return False
    
    def extract_forwarded_ips(self, forwarded_header: str) -> List[str]:
        """
        Extract and validate IP addresses from X-Forwarded-For header.
        
        Args:
            forwarded_header: X-Forwarded-For header value
            
        Returns:
            List of valid IP addresses in order (client first)
        """
        if not forwarded_header:
            return []
        
        # Split by comma and clean up
        ips = [ip.strip() for ip in forwarded_header.split(',')]
        valid_ips = []
        
        for ip in ips:
            # Remove port if present (IPv4:port or [IPv6]:port)
            if ':' in ip and not ip.startswith('['):
                # IPv4 with port
                ip = ip.split(':')[0]
            elif ip.startswith('[') and ']:' in ip:
                # IPv6 with port
                ip = ip.split(']:')[0][1:]
            
            if self.is_valid_ip(ip):
                valid_ips.append(ip)
            else:
                logger.warning(f"Invalid IP in X-Forwarded-For header: {ip}")
        
        return valid_ips
    
    def get_client_ip(self, request: Request) -> str:
        """
        Securely extract client IP address from request with proxy validation.
        
        Implements secure IP detection according to REQ-008:
        - Validates proxy headers against trusted proxy list
        - Falls back to direct connection IP when headers are untrusted
        - Logs potential spoofing attempts
        
        Args:
            request: FastAPI request object
            
        Returns:
            Client IP address string
        """
        # Get direct connection IP as fallback
        direct_ip = request.client.host if request.client else "unknown"
        
        # If no proxy headers, return direct IP
        forwarded_for = request.headers.get("X-Forwarded-For")
        real_ip = request.headers.get("X-Real-IP")
        
        if not forwarded_for and not real_ip:
            return direct_ip
        
        # Validate proxy by checking if direct connection is from trusted network
        if not self.is_trusted_proxy(direct_ip):
            # Direct connection is not from trusted proxy, potential spoofing
            logger.warning(
                f"Potential IP spoofing attempt: proxy headers present but direct IP {direct_ip} "
                f"is not from trusted network. Headers: X-Forwarded-For={forwarded_for}, "
                f"X-Real-IP={real_ip}"
            )
            return direct_ip
        
        # Process X-Real-IP header (simpler, single IP)
        if real_ip and self.is_valid_ip(real_ip):
            logger.debug(f"Using X-Real-IP: {real_ip} (proxy: {direct_ip})")
            return real_ip
        
        # Process X-Forwarded-For header (can contain multiple IPs)
        if forwarded_for:
            forwarded_ips = self.extract_forwarded_ips(forwarded_for)
            
            if forwarded_ips:
                # First IP in the chain should be the original client
                client_ip = forwarded_ips[0]
                
                # Validate the forwarding chain
                if len(forwarded_ips) > 1:
                    # Check if intermediate proxies are trusted
                    for i, proxy_ip in enumerate(forwarded_ips[1:], 1):
                        if not self.is_trusted_proxy(proxy_ip):
                            logger.warning(
                                f"Untrusted proxy in forwarding chain at position {i}: {proxy_ip}. "
                                f"Full chain: {' -> '.join(forwarded_ips)} -> {direct_ip}"
                            )
                            # Still use the client IP but log the concern
                            break
                
                logger.debug(
                    f"Using X-Forwarded-For client IP: {client_ip} "
                    f"(chain: {' -> '.join(forwarded_ips)} -> {direct_ip})"
                )
                return client_ip
        
        # If we get here, proxy headers were present but invalid
        logger.warning(
            f"Invalid proxy headers from trusted proxy {direct_ip}. "
            f"X-Forwarded-For={forwarded_for}, X-Real-IP={real_ip}"
        )
        
        return direct_ip
    
    def is_private_ip(self, ip_str: str) -> bool:
        """
        Check if IP address is from a private network.
        
        Args:
            ip_str: IP address string
            
        Returns:
            True if private IP, False otherwise
        """
        if not self.is_valid_ip(ip_str):
            return False
        
        try:
            ip_addr = ipaddress.ip_address(ip_str)
            return ip_addr.is_private
        except ValueError:
            return False
    
    def get_ip_info(self, ip_str: str) -> dict:
        """
        Get information about an IP address.
        
        Args:
            ip_str: IP address string
            
        Returns:
            Dictionary with IP information
        """
        if not self.is_valid_ip(ip_str):
            return {
                "valid": False,
                "version": None,
                "private": False,
                "loopback": False,
                "trusted_proxy": False
            }
        
        try:
            ip_addr = ipaddress.ip_address(ip_str)
            return {
                "valid": True,
                "version": ip_addr.version,
                "private": ip_addr.is_private,
                "loopback": ip_addr.is_loopback,
                "trusted_proxy": self.is_trusted_proxy(ip_str)
            }
        except ValueError:
            return {
                "valid": False,
                "version": None,
                "private": False,
                "loopback": False,
                "trusted_proxy": False
            }


# Global IP validator instance
_ip_validator = None

def get_ip_validator() -> IPValidator:
    """
    Get global IP validator instance (singleton pattern).
    
    Returns:
        IPValidator instance
    """
    global _ip_validator
    if _ip_validator is None:
        _ip_validator = IPValidator()
    return _ip_validator


def get_client_ip(request: Request) -> str:
    """
    Convenience function to get client IP from request.
    
    Args:
        request: FastAPI request object
        
    Returns:
        Client IP address string
    """
    validator = get_ip_validator()
    return validator.get_client_ip(request)


def is_trusted_proxy(ip_str: str) -> bool:
    """
    Convenience function to check if IP is trusted proxy.
    
    Args:
        ip_str: IP address string
        
    Returns:
        True if trusted proxy, False otherwise
    """
    validator = get_ip_validator()
    return validator.is_trusted_proxy(ip_str)