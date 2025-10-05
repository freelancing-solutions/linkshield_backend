#!/usr/bin/env python3
"""
Test script for IP spoofing protection functionality.
Tests the IPValidator and get_client_ip functions with various scenarios.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from linkshield.utils.ip_utils import IPValidator, get_client_ip
from unittest.mock import Mock

def create_mock_request(client_ip, headers=None):
    """Create a mock FastAPI request object."""
    request = Mock()
    request.client = Mock()
    request.client.host = client_ip
    request.headers = headers or {}
    return request

def test_ip_spoofing_protection():
    """Test IP spoofing protection with various scenarios."""
    print("Testing IP spoofing protection...")
    
    validator = IPValidator()
    
    print("\nTesting IP validation:")
    test_ips = ["192.168.1.1", "10.0.0.1", "127.0.0.1", "8.8.8.8", "invalid-ip"]
    for ip in test_ips:
        is_valid = validator.is_valid_ip(ip)
        print(f"{ip} is valid: {is_valid}")
    
    print("\nTesting trusted proxy validation:")
    proxy_ips = ["127.0.0.1", "10.0.0.1", "8.8.8.8", "192.168.1.1"]
    for ip in proxy_ips:
        is_trusted = validator.is_trusted_proxy(ip)
        print(f"{ip} is trusted: {is_trusted}")
    
    print("\nTesting client IP extraction scenarios:")
    
    # Scenario 1: Direct connection (no proxy headers)
    request1 = create_mock_request("192.168.1.100")
    client_ip1 = validator.get_client_ip(request1)
    print(f"Direct connection IP: {client_ip1}")
    
    # Scenario 2: Trusted proxy with X-Forwarded-For
    request2 = create_mock_request("127.0.0.1", {
        "X-Forwarded-For": "203.0.113.45"
    })
    client_ip2 = validator.get_client_ip(request2)
    print(f"Trusted proxy with X-Forwarded-For: {client_ip2}")
    
    # Scenario 3: Trusted proxy with X-Real-IP
    request3 = create_mock_request("10.0.0.1", {
        "X-Real-IP": "203.0.113.46"
    })
    client_ip3 = validator.get_client_ip(request3)
    print(f"Trusted proxy with X-Real-IP: {client_ip3}")
    
    # Scenario 4: Untrusted proxy with headers (should fallback)
    request4 = create_mock_request("8.8.8.8", {
        "X-Forwarded-For": "203.0.113.47",
        "X-Real-IP": "203.0.113.48"
    })
    client_ip4 = validator.get_client_ip(request4)
    print(f"Untrusted proxy fallback IP: {client_ip4}")
    
    # Scenario 5: Multiple forwarded IPs (proxy chain)
    request5 = create_mock_request("127.0.0.1", {
        "X-Forwarded-For": "203.0.113.49, 10.0.0.5, 192.168.1.10"
    })
    client_ip5 = validator.get_client_ip(request5)
    print(f"Proxy chain client IP: {client_ip5}")
    
    # Scenario 6: Invalid forwarded IP
    request6 = create_mock_request("127.0.0.1", {
        "X-Forwarded-For": "invalid-ip"
    })
    client_ip6 = validator.get_client_ip(request6)
    print(f"Invalid forwarded IP fallback: {client_ip6}")
    
    print("\nTesting extract_forwarded_ips method:")
    test_headers = [
        "203.0.113.1",
        "203.0.113.1, 10.0.0.1",
        "203.0.113.1, 10.0.0.1, 192.168.1.1",
        "203.0.113.1:8080, 10.0.0.1:80",
        "[2001:db8::1]:8080, 203.0.113.1",
        "invalid-ip, 203.0.113.1"
    ]
    
    for header in test_headers:
        ips = validator.extract_forwarded_ips(header)
        print(f"'{header}' -> {ips}")
    
    print("\nIP spoofing protection test completed successfully!")

if __name__ == "__main__":
    test_ip_spoofing_protection()