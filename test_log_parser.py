#!/usr/bin/env python3
"""
Quick Test Script for Log Parser
Tests the nginx log parser with sample log lines
"""

import sys
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).parent))

from src.log_parser import NginxLogParser


def test_parser():
    """Test the log parser with various log formats"""
    
    parser = NginxLogParser()
    
    print("="*80)
    print("Testing Nginx Log Parser")
    print("="*80)
    
    # Test cases
    test_logs = [
        # SQL Injection attempt
        '192.168.1.100 - - [29/Nov/2025:10:30:45 +0000] "GET http://localhost:8080/vulnerabilities/sqli/?id=1%27%20OR%20%271%27=%271 HTTP/1.1" 200 1234 "http://localhost:8080/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" "-" request_time=0.123 upstream_response_time=0.100 request_body="" query_string="id=1%27%20OR%20%271%27=%271" content_type="-" content_length="-"',
        
        # Normal POST request
        '10.0.0.50 - admin [29/Nov/2025:10:31:00 +0000] "POST http://localhost:8090/api/login HTTP/1.1" 200 567 "http://localhost:8090/login" "curl/7.68.0" "192.168.1.1" request_time=0.234 upstream_response_time=0.200 request_body="username=admin&password=test123" query_string="" content_type="application/x-www-form-urlencoded" content_length="35"',
        
        # XSS attempt
        '172.16.0.1 - - [29/Nov/2025:10:32:15 +0000] "GET http://localhost:8091/search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1" 200 890 "-" "Mozilla/5.0" "-" request_time=0.089 upstream_response_time=0.075 request_body="" query_string="q=%3Cscript%3Ealert(1)%3C/script%3E" content_type="-" content_length="-"',
        
        # Normal GET
        '192.168.1.50 - - [29/Nov/2025:10:33:00 +0000] "GET http://localhost:8080/index.php HTTP/1.1" 200 5432 "http://localhost:8080/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)" "-" request_time=0.045 upstream_response_time=0.030 request_body="" query_string="" content_type="-" content_length="-"',
    ]
    
    for i, log in enumerate(test_logs, 1):
        print(f"\n{'='*80}")
        print(f"Test Case {i}")
        print(f"{'='*80}")
        print(f"Raw Log: {log[:100]}...")
        
        result = parser.parse_line(log)
        
        if result:
            print(f"\n✓ Successfully Parsed:")
            print(f"  Remote IP:  {result['remote_addr']}")
            print(f"  Method:     {result['method']}")
            print(f"  Path:       {result['path']}")
            print(f"  Query:      {result['query']}")
            print(f"  Body:       {result['body'][:50] if result['body'] else 'None'}...")
            print(f"  User-Agent: {result['headers']['user-agent'][:50]}...")
            print(f"  Status:     {result['status']}")
            
            # Show detector format
            detector_req = parser.extract_request_for_detector(result)
            print(f"\n  Detector Format Preview:")
            print(f"    Method: {detector_req['method']}")
            print(f"    Path:   {detector_req['path']}")
            if detector_req['query']:
                print(f"    Query:  {list(detector_req['query'].keys())}")
        else:
            print(f"\n✗ Failed to parse!")
    
    print(f"\n{'='*80}")
    print("✓ All tests completed")
    print(f"{'='*80}")


if __name__ == '__main__':
    test_parser()
