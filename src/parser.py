"""
Advanced Log Parser and Normalizer for WAF Pipeline
Extracts and normalizes key fields from Apache/Nginx access logs
Author: ISRO WAF Team
"""

import os
import re
import json
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, unquote
from dataclasses import dataclass, asdict
import hashlib


@dataclass
class ParsedRequest:
    """Structured representation of a parsed HTTP request"""
    method: str
    path: str
    normalized_path: str
    query_params: Dict[str, str]
    status_code: int
    content_type: str
    content_length: int
    request_body: str
    user_agent: str
    referer: str
    has_query: bool
    has_body: bool
    path_depth: int
    file_extension: str
    
    def to_text_sequence(self) -> str:
        """Convert parsed request to a text sequence for transformer input"""
        parts = [
            f"METHOD:{self.method}",
            f"PATH:{self.normalized_path}",
            f"STATUS:{self.status_code}",
        ]
        
        if self.query_params:
            query_str = " ".join([f"{k}={v}" for k, v in self.query_params.items()])
            parts.append(f"QUERY:{query_str}")
        
        if self.has_body and self.request_body != "-":
            parts.append(f"BODY:{self.request_body}")
        
        if self.content_type and self.content_type != "-":
            parts.append(f"CONTENT_TYPE:{self.content_type}")
        
        if self.file_extension:
            parts.append(f"EXT:{self.file_extension}")
        
        return " ".join(parts)


class LogParser:
    """
    Advanced parser for Apache/Nginx access logs
    Handles custom log format with extended fields
    """
    
    # Regex pattern for the custom log format
    LOG_PATTERN = re.compile(
        r'(?P<ip>[\d\.]+) - (?P<user>.*?) \[(?P<timestamp>.*?)\] '
        r'"(?P<method>\w+) (?P<url>.*?) (?P<protocol>HTTP/[\d\.]+)" '
        r'(?P<status>\d+) (?P<bytes>\d+) "(?P<referer>.*?)" "(?P<user_agent>.*?)" '
        r'"(?P<forwarded>.*?)" request_time=(?P<request_time>[\d\.]+) '
        r'upstream_response_time=(?P<upstream_time>[\d\.]+) '
        r'request_body="(?P<request_body>.*?)" '
        r'query_string="(?P<query_string>.*?)" '
        r'content_type="(?P<content_type>.*?)" '
        r'content_length="(?P<content_length>.*?)"'
    )
    
    # Patterns for normalization
    UUID_PATTERN = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.IGNORECASE)
    NUMERIC_ID_PATTERN = re.compile(r'/\d+(?=/|$)')
    HEX_ID_PATTERN = re.compile(r'/[0-9a-f]{32,}(?=/|$)', re.IGNORECASE)
    TOKEN_PATTERN = re.compile(r'[a-zA-Z0-9]{32,}')
    EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
    
    def __init__(self):
        self.parsed_count = 0
        self.error_count = 0
    
    def parse_line(self, line: str) -> Optional[ParsedRequest]:
        """
        Parse a single log line into a structured format
        
        Args:
            line: Raw log line string
            
        Returns:
            ParsedRequest object or None if parsing fails
        """
        line = line.strip()
        if not line:
            return None
        
        match = self.LOG_PATTERN.match(line)
        if not match:
            self.error_count += 1
            return None
        
        try:
            data = match.groupdict()
            
            # Parse URL components
            url = data['url']
            parsed_url = urlparse(url)
            path = parsed_url.path
            
            # Normalize path
            normalized_path = self._normalize_path(path)
            
            # Parse query parameters
            query_params = {}
            query_string = data.get('query_string', '-')
            if query_string and query_string != '-':
                query_params = self._parse_query_string(query_string)
            elif parsed_url.query:
                query_params = self._parse_query_string(parsed_url.query)
            
            # Normalize query parameters
            normalized_params = self._normalize_query_params(query_params)
            
            # Extract file extension
            file_extension = self._extract_extension(path)
            
            # Parse request body
            request_body = data.get('request_body', '-')
            if request_body and request_body != '-':
                request_body = self._normalize_body(request_body)
            
            # Calculate path depth
            path_depth = len([p for p in path.split('/') if p])
            
            parsed_request = ParsedRequest(
                method=data['method'],
                path=path,
                normalized_path=normalized_path,
                query_params=normalized_params,
                status_code=int(data['status']),
                content_type=data.get('content_type', '-'),
                content_length=self._parse_int(data.get('content_length', '-')),
                request_body=request_body,
                user_agent=self._normalize_user_agent(data['user_agent']),
                referer=data.get('referer', '-'),
                has_query=bool(normalized_params),
                has_body=(request_body != '-' and request_body),
                path_depth=path_depth,
                file_extension=file_extension
            )
            
            self.parsed_count += 1
            return parsed_request
            
        except Exception as e:
            self.error_count += 1
            print(f"Error parsing line: {e}")
            return None
    
    def _normalize_path(self, path: str) -> str:
        """
        Normalize URL path by removing dynamic IDs, UUIDs, tokens
        
        Examples:
            /user/12345/profile -> /user/{id}/profile
            /api/v1/items/abc123def456 -> /api/v1/items/{id}
        """
        # Remove UUIDs
        path = self.UUID_PATTERN.sub('{uuid}', path)
        
        # Remove numeric IDs
        path = self.NUMERIC_ID_PATTERN.sub('/{id}', path)
        
        # Remove hex IDs (like tokens)
        path = self.HEX_ID_PATTERN.sub('/{hex_id}', path)
        
        # Normalize multiple slashes
        path = re.sub(r'/+', '/', path)
        
        return path
    
    def _normalize_query_params(self, params: Dict[str, str]) -> Dict[str, str]:
        """
        Normalize query parameter values
        Removes specific values but keeps parameter structure
        """
        normalized = {}
        for key, value in params.items():
            # Keep parameter name, normalize value
            if self.UUID_PATTERN.match(value):
                normalized[key] = '{uuid}'
            elif value.isdigit():
                normalized[key] = '{num}'
            elif self.TOKEN_PATTERN.match(value) and len(value) > 20:
                normalized[key] = '{token}'
            elif self.EMAIL_PATTERN.match(value):
                normalized[key] = '{email}'
            else:
                # Keep the value but truncate if too long
                normalized[key] = value[:50] if len(value) > 50 else value
        
        return normalized
    
    def _normalize_body(self, body: str) -> str:
        """
        Normalize request body content
        Removes dynamic values while preserving structure
        """
        # Try to parse as URL-encoded form data
        if '&' in body and '=' in body:
            parts = []
            for part in body.split('&'):
                if '=' in part:
                    key, value = part.split('=', 1)
                    # Normalize the value
                    value = unquote(value)
                    if len(value) > 20 and self.TOKEN_PATTERN.match(value):
                        parts.append(f"{key}={{token}}")
                    elif value.isdigit():
                        parts.append(f"{key}={{num}}")
                    else:
                        parts.append(f"{key}={value[:30]}")
                else:
                    parts.append(part)
            return '&'.join(parts)
        
        # Try to parse as JSON
        elif body.startswith('{') or body.startswith('['):
            try:
                # Just validate it's JSON, keep structure info
                json.loads(body.replace('\\x22', '"'))
                return '{json_body}'
            except:
                pass
        
        # Return truncated body
        return body[:100] if len(body) > 100 else body
    
    def _normalize_user_agent(self, user_agent: str) -> str:
        """
        Normalize user agent string to browser/version category
        """
        if 'Chrome' in user_agent:
            return 'Chrome'
        elif 'Firefox' in user_agent:
            return 'Firefox'
        elif 'Safari' in user_agent and 'Chrome' not in user_agent:
            return 'Safari'
        elif 'Edge' in user_agent:
            return 'Edge'
        elif 'curl' in user_agent.lower():
            return 'curl'
        elif 'python' in user_agent.lower():
            return 'python'
        else:
            return 'Other'
    
    def _parse_query_string(self, query_string: str) -> Dict[str, str]:
        """Parse query string into dictionary"""
        if not query_string or query_string == '-':
            return {}
        
        params = {}
        try:
            parsed = parse_qs(query_string, keep_blank_values=True)
            # Flatten lists (take first value)
            for key, value_list in parsed.items():
                params[key] = value_list[0] if value_list else ''
        except:
            pass
        
        return params
    
    def _extract_extension(self, path: str) -> str:
        """Extract file extension from path"""
        if '.' in path.split('/')[-1]:
            return path.split('.')[-1].lower()
        return ''
    
    def _parse_int(self, value: str) -> int:
        """Safely parse integer from string"""
        try:
            return int(value) if value != '-' else 0
        except:
            return 0
    
    def parse_file(self, filepath: str) -> List[ParsedRequest]:
        """
        Parse entire log file
        
        Args:
            filepath: Path to log file
            
        Returns:
            List of ParsedRequest objects
        """
        parsed_requests = []
        
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                parsed = self.parse_line(line)
                if parsed:
                    parsed_requests.append(parsed)
                
                if line_num % 1000 == 0:
                    print(f"Processed {line_num} lines, parsed {self.parsed_count}, errors {self.error_count}")
        
        return parsed_requests
    
    def get_stats(self) -> Dict:
        """Get parsing statistics"""
        total = self.parsed_count + self.error_count
        success_rate = (self.parsed_count / total * 100) if total > 0 else 0
        
        return {
            'total_lines': total,
            'parsed': self.parsed_count,
            'errors': self.error_count,
            'success_rate': f"{success_rate:.2f}%"
        }


def save_parsed_requests(parsed_requests: List[ParsedRequest], output_path: str):
    """
    Save parsed requests to disk for later use
    
    Args:
        parsed_requests: List of ParsedRequest objects
        output_path: Path to save file (JSON format)
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # Convert dataclass objects to dictionaries
    serialized = [asdict(req) for req in parsed_requests]
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(serialized, f, indent=2)
    
    print(f"✓ Saved {len(parsed_requests)} parsed requests to {output_path}")


def load_parsed_requests(input_path: str) -> List[ParsedRequest]:
    """
    Load parsed requests from disk
    
    Args:
        input_path: Path to saved file
        
    Returns:
        List of ParsedRequest objects
    """
    with open(input_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    parsed_requests = [ParsedRequest(**item) for item in data]
    print(f"✓ Loaded {len(parsed_requests)} parsed requests from {input_path}")
    
    return parsed_requests


def parse_all_logs_in_directory(log_dir: str = "logs") -> List[ParsedRequest]:
    """
    Parse all .log files in a directory
    
    Args:
        log_dir: Directory containing log files
        
    Returns:
        Combined list of all parsed requests from all log files
    """
    import glob
    
    all_parsed_requests = []
    log_files = glob.glob(os.path.join(log_dir, "*.log"))
    
    if not log_files:
        print(f"No .log files found in {log_dir}/")
        return all_parsed_requests
    
    print(f"\n{'='*70}")
    print(f"Found {len(log_files)} log file(s) in {log_dir}/")
    print(f"{'='*70}\n")
    
    for log_file in sorted(log_files):
        filename = os.path.basename(log_file)
        print(f"\n📄 Processing: {filename}")
        print(f"   Path: {log_file}")
        
        parser = LogParser()
        try:
            parsed_requests = parser.parse_file(log_file)
            
            stats = parser.get_stats()
            print(f"   ✓ Parsed: {stats['parsed']} requests")
            print(f"   ✗ Errors: {stats['errors']}")
            print(f"   Success Rate: {stats['success_rate']}")
            
            all_parsed_requests.extend(parsed_requests)
            
        except Exception as e:
            print(f"   ❌ Error parsing {filename}: {e}")
            continue
    
    print(f"\n{'='*70}")
    print(f"Total parsed requests from all files: {len(all_parsed_requests)}")
    print(f"{'='*70}\n")
    
    return all_parsed_requests


def main():
    """Test the parser"""
    import sys
    import glob
    
    if len(sys.argv) < 2:
        print("No arguments provided. Checking for log files...")
        
        # Check if logs directory exists
        if os.path.exists("logs") and glob.glob("logs/*.log"):
            print("✓ Found logs directory with .log files")
            print("\nParsing ALL log files in logs/ directory...")
            parsed_requests = parse_all_logs_in_directory("logs")
            
            if not parsed_requests:
                print("\n⚠ No requests parsed. Using sample data instead...")
                from sample_data import get_sample_logs
                parser = LogParser()
                parsed_requests = []
                for line in get_sample_logs():
                    parsed = parser.parse_line(line)
                    if parsed:
                        parsed_requests.append(parsed)
            
            output_file = "data/parsed/parsed_requests.json"
        else:
            print("No logs directory found. Using built-in sample data...")
            from sample_data import get_sample_logs
            parser = LogParser()
            parsed_requests = []
            for line in get_sample_logs():
                parsed = parser.parse_line(line)
                if parsed:
                    parsed_requests.append(parsed)
            output_file = "data/parsed/parsed_requests.json"
    else:
        log_file = sys.argv[1]
        output_file = sys.argv[2] if len(sys.argv) > 2 else "data/parsed/parsed_requests.json"
        
        parser = LogParser()
        print(f"Parsing {log_file}...")
        parsed_requests = parser.parse_file(log_file)
        
        stats = parser.get_stats()
        print(f"\n=== Parsing Statistics ===")
        for key, value in stats.items():
            print(f"{key}: {value}")
    
    # Save parsed requests
    save_parsed_requests(parsed_requests, output_file)
    
    print(f"\n=== Sample Parsed Requests (first 5) ===")
    for i, req in enumerate(parsed_requests[:5]):
        print(f"\nRequest {i+1}:")
        print(f"  Original Path: {req.path}")
        print(f"  Normalized Path: {req.normalized_path}")
        print(f"  Method: {req.method}")
        print(f"  Status: {req.status_code}")
        print(f"  Text Sequence: {req.to_text_sequence()[:80]}...")
    
    print(f"\n{'='*70}")
    print(f"✓ Pipeline complete!")
    print(f"  Total requests: {len(parsed_requests)}")
    print(f"  Output file: {output_file}")
    print(f"\nNext step: python3 src/tokenizer.py")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
