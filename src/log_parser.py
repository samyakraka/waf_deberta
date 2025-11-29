#!/usr/bin/env python3
"""
Real-Time WAF Log Parser for Nginx Detailed Format
Parses nginx waf_detailed log format and extracts request information
for classification by the WAF detector.

Author: ISRO WAF Team
"""

import re
from typing import Dict, Optional
from urllib.parse import parse_qs, urlparse
from datetime import datetime


class NginxLogParser:
    """
    Parser for nginx waf_detailed log format:
    '$remote_addr - $remote_user [$time_local] '
    '"$request_method $scheme://$host$request_uri $server_protocol" '
    '$status $body_bytes_sent '
    '"$http_referer" "$http_user_agent" '
    '"$http_x_forwarded_for" '
    'request_time=$request_time '
    'upstream_response_time=$upstream_response_time '
    'request_body="$request_body" '
    'query_string="$query_string" '
    'content_type="$content_type" '
    'content_length="$content_length"'
    """
    
    def __init__(self):
        # Comprehensive regex pattern for the waf_detailed format
        self.log_pattern = re.compile(
            r'^(?P<remote_addr>[\d\.]+) - (?P<remote_user>[\w\-]+|\-) '
            r'\[(?P<time_local>[^\]]+)\] '
            r'"(?P<request_method>\w+) (?P<request_uri>[^\s]+) (?P<server_protocol>[^"]+)" '
            r'(?P<status>\d+) (?P<body_bytes_sent>\d+) '
            r'"(?P<http_referer>[^"]*)" "(?P<http_user_agent>[^"]*)" '
            r'"(?P<http_x_forwarded_for>[^"]*)" '
            r'request_time=(?P<request_time>[\d\.\-]+) '
            r'upstream_response_time=(?P<upstream_response_time>[\d\.\-]+) '
            r'request_body="(?P<request_body>[^"]*)" '
            r'query_string="(?P<query_string>[^"]*)" '
            r'content_type="(?P<content_type>[^"]*)" '
            r'content_length="(?P<content_length>[^"]*)"'
        )
    
    def parse_line(self, line: str) -> Optional[Dict]:
        """
        Parse a single nginx log line
        
        Args:
            line: Raw log line from nginx
            
        Returns:
            Dictionary with parsed request data, or None if parsing fails
        """
        match = self.log_pattern.match(line.strip())
        if not match:
            return None
        
        data = match.groupdict()
        
        # Parse the full URI to extract path and query parameters
        try:
            parsed_uri = urlparse(data['request_uri'])
            path = parsed_uri.path
            query_params = parse_qs(parsed_uri.query) if parsed_uri.query else {}
            
            # Also parse the query_string field (may contain additional info)
            if data['query_string']:
                additional_params = parse_qs(data['query_string'])
                query_params.update(additional_params)
        except Exception:
            path = data['request_uri']
            query_params = {}
        
        # Build the request dictionary for the WAF detector
        request = {
            'method': data['request_method'],
            'path': path,
            'query': {k: v[0] if len(v) == 1 else v for k, v in query_params.items()},
            'headers': {
                'user-agent': data['http_user_agent'],
                'referer': data['http_referer'],
                'content-type': data['content_type'],
                'content-length': data['content_length'],
            },
            'body': data['request_body'] if data['request_body'] else None,
            'remote_addr': data['remote_addr'],
            'status': int(data['status']),
            'timestamp': data['time_local'],
        }
        
        # Add raw log data for reference
        request['raw_log'] = line.strip()
        
        return request
    
    def extract_request_for_detector(self, parsed_request: Dict) -> Dict:
        """
        Extract only the fields needed by the WAF detector
        
        Args:
            parsed_request: Full parsed request dictionary
            
        Returns:
            Simplified request dict for detector
        """
        return {
            'method': parsed_request['method'],
            'path': parsed_request['path'],
            'query': parsed_request['query'],
            'headers': {
                k: v for k, v in parsed_request['headers'].items() 
                if v and v != '-'
            },
            'body': parsed_request['body'],
        }


# Test function
if __name__ == '__main__':
    parser = NginxLogParser()
    
    # Test with sample log lines
    test_logs = [
        '192.168.1.100 - - [29/Nov/2025:10:30:45 +0000] "GET http://localhost:8080/vulnerabilities/sqli/?id=1%27%20OR%20%271%27=%271 HTTP/1.1" 200 1234 "http://localhost:8080/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" "-" request_time=0.123 upstream_response_time=0.100 request_body="" query_string="id=1%27%20OR%20%271%27=%271" content_type="-" content_length="-"',
        '10.0.0.50 - admin [29/Nov/2025:10:31:00 +0000] "POST http://localhost:8090/api/login HTTP/1.1" 200 567 "http://localhost:8090/login" "curl/7.68.0" "192.168.1.1" request_time=0.234 upstream_response_time=0.200 request_body="username=admin&password=test123" query_string="" content_type="application/x-www-form-urlencoded" content_length="35"',
    ]
    
    for log in test_logs:
        result = parser.parse_line(log)
        if result:
            print(f"\n✓ Parsed successfully:")
            print(f"  Method: {result['method']}")
            print(f"  Path: {result['path']}")
            print(f"  Query: {result['query']}")
            print(f"  Body: {result['body']}")
        else:
            print(f"\n✗ Failed to parse: {log[:80]}...")
