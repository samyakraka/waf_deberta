#!/usr/bin/env python3
"""
Signature Manager for Incremental Redis Rules
Extracts attack patterns from ML-detected attacks and manages signature approvals

Author: ISRO WAF Team
"""

import json
import re
import os
from datetime import datetime
from typing import Dict, List, Set
from collections import defaultdict
from pathlib import Path


class SignatureManager:
    """Manages attack log collection and signature extraction"""
    
    def __init__(self, attack_logs_file: str = "data/parsed/new_attack_logs.json"):
        self.attack_logs_file = attack_logs_file
        self.attack_logs = []
        self._load_attack_logs()
        
    def _load_attack_logs(self):
        """Load existing attack logs from file"""
        if os.path.exists(self.attack_logs_file):
            try:
                with open(self.attack_logs_file, 'r') as f:
                    self.attack_logs = json.load(f)
                print(f"✅ Loaded {len(self.attack_logs)} attack logs")
            except Exception as e:
                print(f"⚠️  Failed to load attack logs: {e}")
                self.attack_logs = []
        else:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(self.attack_logs_file), exist_ok=True)
            self.attack_logs = []
    
    def add_attack_log(self, request_dict: dict, result):
        """Add a detected attack to the logs"""
        try:
            attack_entry = {
                'timestamp': datetime.now().isoformat(),
                'method': request_dict.get('method', 'GET'),
                'path': request_dict.get('path', '/'),
                'query': request_dict.get('query', {}),
                'headers': request_dict.get('headers', {}),
                'body': request_dict.get('body', None),
                'detection_method': result.detection_method,
                'threat_type': result.threat_type,
                'confidence': result.confidence,
                'risk_level': result.risk_level,
                'matched_patterns': getattr(result, 'matched_patterns', [])
            }
            
            self.attack_logs.append(attack_entry)
            self._save_attack_logs()
            
        except Exception as e:
            print(f"⚠️  Failed to add attack log: {e}")
    
    def _save_attack_logs(self):
        """Save attack logs to file"""
        try:
            with open(self.attack_logs_file, 'w') as f:
                json.dump(self.attack_logs, f, indent=2)
        except Exception as e:
            print(f"⚠️  Failed to save attack logs: {e}")
    
    def get_attack_count(self) -> int:
        """Get number of attack logs"""
        return len(self.attack_logs)
    
    def extract_signatures(self) -> Dict[str, Set[str]]:
        """
        Extract signature patterns from attack logs
        Returns a dict mapping category to set of patterns
        """
        signatures = defaultdict(set)
        
        for log in self.attack_logs:
            threat_type = log.get('threat_type', 'Unknown')
            method = log.get('method', 'GET')
            path = log.get('path', '')
            query = log.get('query', {})
            body = log.get('body', '')
            headers = log.get('headers', {})
            
            # Map threat types to categories
            category_map = {
                'SQL Injection': 'sqli_patterns',
                'XSS': 'xss_patterns',
                'Path Traversal': 'path_traversal_patterns',
                'Command Injection': 'cmd_injection_patterns',
                'LDAP Injection': 'ldap_injection_patterns',
                'XXE': 'xxe_patterns',
                'SSRF': 'ssrf_patterns',
                'RFI': 'rfi_patterns',
                'LFI': 'lfi_patterns',
                'NoSQL Injection': 'nosql_injection_patterns',
                'CRLF Injection': 'crlf_injection_patterns',
                'Template Injection': 'template_injection_patterns',
                'Deserialization': 'deserialization_patterns',
                'HPP': 'hpp_patterns',
                'Shellshock': 'shellshock_patterns',
                'Webshell': 'webshell_patterns',
                'Auth Bypass': 'auth_bypass_patterns',
            }
            
            category = category_map.get(threat_type, 'suspicious_patterns')
            
            # ENHANCED: For Anomaly type, try to classify based on request characteristics
            if threat_type == 'Anomaly':
                category = self._classify_anomaly(headers, path, query, body, method)
                print(f"🔍 Classified anomaly as: {category}")
            
            # ENHANCED: Extract patterns from headers first (critical for HTTP smuggling, etc.)
            if isinstance(headers, dict):
                header_patterns = self._extract_header_patterns(headers)
                for hp_category, hp_pattern in header_patterns:
                    if hp_pattern:
                        signatures[hp_category].add(hp_pattern)
                        print(f"✅ Extracted header pattern for {hp_category}")
            
            # Extract patterns from query parameters
            if isinstance(query, dict):
                for key, value in query.items():
                    if value:
                        # Convert value to string and extract potential attack pattern
                        val_str = str(value) if not isinstance(value, list) else ' '.join(map(str, value))
                        pattern = self._extract_pattern_from_value(val_str)
                        if pattern:
                            signatures[category].add(pattern)
                            print(f"✅ Extracted query pattern for {category}: {pattern[:50]}...")
            
            # Extract patterns from body
            if body:
                pattern = self._extract_pattern_from_value(str(body))
                if pattern:
                    signatures[category].add(pattern)
                    print(f"✅ Extracted body pattern for {category}")
            
            # Extract patterns from path (ENHANCED: also extract simple suspicious paths)
            if path:
                # Check for path traversal
                if any(sus in path.lower() for sus in ['../', '.\\', 'etc/', 'passwd', 'shadow']):
                    pattern = self._extract_pattern_from_value(path)
                    if pattern:
                        signatures['path_traversal_patterns'].add(pattern)
                        print(f"✅ Extracted path traversal pattern")
                # For anomalies, also extract the path itself as a pattern
                elif threat_type == 'Anomaly' and len(path) > 1:
                    # Create a simple path pattern for suspicious requests
                    path_pattern = re.escape(path)
                    signatures[category].add(path_pattern)
                    print(f"✅ Extracted anomaly path pattern: {path}")
        
        # Convert sets to lists for JSON serialization
        return {k: list(v) for k, v in signatures.items()}
    
    def _classify_anomaly(self, headers: dict, path: str, query: dict, body: str, method: str) -> str:
        """
        Classify anomaly type based on request characteristics
        This helps categorize generic 'Anomaly' detections into specific threat types
        """
        # Check headers for specific attack indicators
        if isinstance(headers, dict):
            header_keys_lower = {k.lower(): v for k, v in headers.items()}
            
            # HTTP Request Smuggling / Chunked Transfer Encoding abuse
            if 'transfer-encoding' in header_keys_lower:
                te_value = str(header_keys_lower['transfer-encoding']).lower()
                if 'chunked' in te_value:
                    return 'http_smuggling_patterns'
            
            # Content-Type anomalies
            if 'content-type' in header_keys_lower:
                ct_value = str(header_keys_lower['content-type']).lower()
                if any(sus in ct_value for sus in ['../','..\\','script','exec']):
                    return 'suspicious_patterns'
            
            # Shellshock in User-Agent or other headers
            for header_val in headers.values():
                if header_val and '() {' in str(header_val):
                    return 'shellshock_patterns'
        
        # Check path for traversal
        if path and any(sus in path.lower() for sus in ['../', '.\\', '/etc/', 'passwd', 'shadow', 'win.ini']):
            return 'path_traversal_patterns'
        
        # Check for command injection indicators
        combined_text = f"{path} {str(query)} {str(body)}"
        if any(cmd in combined_text for cmd in ['|', '&&', '||', ';', '`', '$(',  'wget', 'curl']):
            return 'cmd_injection_patterns'
        
        # Default to suspicious patterns
        return 'suspicious_patterns'
    
    def _extract_header_patterns(self, headers: dict) -> List[Tuple[str, str]]:
        """
        Extract attack patterns from HTTP headers
        Returns list of (category, pattern) tuples
        """
        patterns = []
        
        if not isinstance(headers, dict):
            return patterns
        
        # Normalize header keys to lowercase for comparison
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        # HTTP Request Smuggling Detection (Transfer-Encoding)
        if 'transfer-encoding' in headers_lower:
            te_value = str(headers_lower['transfer-encoding'])
            # Create pattern for Transfer-Encoding: chunked abuse
            pattern = r'Transfer-Encoding:\s*chunked'
            patterns.append(('http_smuggling_patterns', pattern))
            print(f"🔍 Extracted HTTP smuggling pattern: {pattern}")
        
        # Content-Length anomalies (multiple Content-Length headers)
        content_length_count = sum(1 for k in headers.keys() if k.lower() == 'content-length')
        if content_length_count > 1:
            pattern = r'Content-Length:.*\r\n.*Content-Length:'
            patterns.append(('http_smuggling_patterns', pattern))
        
        # Shellshock in headers
        for header_name, header_value in headers.items():
            if header_value and '() {' in str(header_value):
                # Extract shellshock pattern
                pattern = r'\(\)\s*\{[^}]*\}\s*;'
                patterns.append(('shellshock_patterns', pattern))
                print(f"🔍 Extracted Shellshock pattern from header {header_name}")
                break
        
        # CRLF Injection in headers
        for header_name, header_value in headers.items():
            if header_value and ('\r\n' in str(header_value) or '\n' in str(header_value)):
                pattern = r'\r\n|\n'
                patterns.append(('crlf_injection_patterns', pattern))
                print(f"🔍 Extracted CRLF injection pattern from header {header_name}")
                break
        
        # Suspicious User-Agent patterns
        if 'user-agent' in headers_lower:
            ua = str(headers_lower['user-agent']).lower()
            if any(suspicious in ua for suspicious in ['nmap', 'sqlmap', 'nikto', 'masscan', 'scanner']):
                pattern = re.escape(headers_lower['user-agent'])
                patterns.append(('blocked_user_agents', pattern))
                print(f"🔍 Extracted suspicious User-Agent pattern")
        
        return patterns
    
    def _extract_pattern_from_value(self, value: str) -> str:
        """
        Extract a regex pattern from an attack value
        This creates a flexible pattern that can match similar attacks
        """
        if not value or len(value) < 3:
            return None
        
        # Clean and escape the value
        value = value.strip()
        
        # Common attack indicators to create patterns around
        attack_indicators = [
            # SQL Injection
            (r"(\bOR\b|\bAND\b)\s*['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?", r"(\bOR\b|\bAND\b)\s*['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?"),
            (r"UNION\s+SELECT", r"UNION\s+SELECT"),
            (r"--\s*$", r"--\s*$"),
            (r";\s*DROP\s+TABLE", r";\s*DROP\s+TABLE"),
            
            # Path Traversal
            (r"\.\./", r"\.\./"),
            (r"\.\\/", r"\.\\/"),
            (r"/etc/passwd", r"/etc/passwd"),
            (r"/etc/shadow", r"/etc/shadow"),
            
            # XSS
            (r"<script[^>]*>", r"<script[^>]*>"),
            (r"javascript:", r"javascript:"),
            (r"onerror\s*=", r"onerror\s*="),
            (r"onload\s*=", r"onload\s*="),
            
            # Command Injection
            (r";\s*(ls|cat|wget|curl|bash|sh)\b", r";\s*(ls|cat|wget|curl|bash|sh)\b"),
            (r"\|\s*(ls|cat|wget|curl|bash|sh)\b", r"\|\s*(ls|cat|wget|curl|bash|sh)\b"),
            (r"&&\s*(ls|cat|wget|curl|bash|sh)\b", r"&&\s*(ls|cat|wget|curl|bash|sh)\b"),
        ]
        
        # Check if value matches any attack indicator
        for indicator_regex, pattern_template in attack_indicators:
            if re.search(indicator_regex, value, re.IGNORECASE):
                return pattern_template
        
        # For other cases, create a generalized pattern
        # Escape special regex characters but keep some flexibility
        pattern = re.escape(value)
        
        # Make numbers flexible
        pattern = re.sub(r'\\d+', r'\\d+', pattern)
        
        # Make whitespace flexible
        pattern = re.sub(r'\\\s+', r'\\s+', pattern)
        
        # LOWERED THRESHOLD: Return pattern if it's at least 3 chars (was 10)
        # This allows simple anomaly patterns to be extracted
        if len(pattern) >= 3:
            return pattern
        
        return None
    
    def get_pending_signatures(self) -> Dict:
        """
        Get extracted signatures that are pending admin approval
        Returns signatures organized by category with metadata
        """
        signatures = self.extract_signatures()
        
        return {
            'total_attacks': len(self.attack_logs),
            'signature_categories': len(signatures),
            'total_patterns': sum(len(patterns) for patterns in signatures.values()),
            'signatures': signatures,
            'timestamp': datetime.now().isoformat()
        }
    
    def clear_attack_logs(self, backup: bool = True) -> int:
        """
        Clear attack logs, optionally creating a backup
        Returns number of logs cleared
        """
        count = len(self.attack_logs)
        
        if backup and count > 0:
            backup_file = f"data/parsed/attack_logs_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            try:
                with open(backup_file, 'w') as f:
                    json.dump(self.attack_logs, f, indent=2)
                print(f"✅ Backed up {count} attack logs to {backup_file}")
            except Exception as e:
                print(f"⚠️  Failed to backup attack logs: {e}")
        
        self.attack_logs = []
        self._save_attack_logs()
        
        return count
    
    def get_stats(self) -> Dict:
        """Get statistics about attack logs"""
        if not self.attack_logs:
            return {
                'total_attacks': 0,
                'by_threat_type': {},
                'by_detection_method': {},
                'by_risk_level': {}
            }
        
        threat_types = defaultdict(int)
        detection_methods = defaultdict(int)
        risk_levels = defaultdict(int)
        
        for log in self.attack_logs:
            threat_types[log.get('threat_type', 'Unknown')] += 1
            detection_methods[log.get('detection_method', 'Unknown')] += 1
            risk_levels[log.get('risk_level', 'Unknown')] += 1
        
        return {
            'total_attacks': len(self.attack_logs),
            'by_threat_type': dict(threat_types),
            'by_detection_method': dict(detection_methods),
            'by_risk_level': dict(risk_levels)
        }


# Global instance
_signature_manager = None


def get_signature_manager() -> SignatureManager:
    """Get or create the global signature manager instance"""
    global _signature_manager
    if _signature_manager is None:
        _signature_manager = SignatureManager()
    return _signature_manager
