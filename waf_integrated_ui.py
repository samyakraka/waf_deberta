#!/usr/bin/env python3
"""
Integrated WAF Testing & Log Analysis UI
- Live hierarchical WAF testing with curl commands
- Real-time log monitoring from 3 applications (DVWA, Juice Shop, WebGoat)
- Log analysis with ML-based classification
- Single unified interface with web UI

Author: ISRO WAF Team
"""

import os
os.environ['TOKENIZERS_PARALLELISM'] = 'false'
os.environ['WANDB_DISABLED'] = 'true'

import sys
import json
import re
import time
import subprocess
import threading
from pathlib import Path
from datetime import datetime
from collections import deque
from functools import lru_cache
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from flask import Flask, request, jsonify, render_template_string, session
import logging
import secrets

# Add src to path
sys.path.append(str(Path(__file__).parent))

from src.detector import WAFDetector
from src.redis_rules import RedisRuleManager
from static_rules import STATIC_RULES
from incremental_model import get_incremental_manager
from signature_manager import get_signature_manager

# ============================================================================
# CONFIGURATION
# ============================================================================

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # For session management
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# Global state
detector = None
redis_manager = None
compiled_rules = {}
detection_log = deque(maxlen=1000)
test_results = deque(maxlen=100)
log_monitor_results = deque(maxlen=500)
monitoring_active = False
monitoring_threads = []
incremental_manager = None
signature_manager = None

# Admin authentication
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "password"
admin_sessions = set()

# Log files to monitor
LOG_FILES = {
    'DVWA': 'nginx/logs/dvwa-access.log',
    'JuiceShop': 'nginx/logs/juiceshop-access.log',
    'WebGoat': 'nginx/logs/webgoat-access.log'
}

# ============================================================================
# REDIS-BASED RULE DETECTION (400+ Patterns)
# ============================================================================

def initialize_redis_rules():
    """Initialize Redis with comprehensive rules or use static fallback"""
    global redis_manager, compiled_rules
    
    try:
        # Try to connect to Redis
        redis_manager = RedisRuleManager(host='localhost', port=6379, db=0)
        
        # Check if rules exist, if not initialize them
        rule_counts = redis_manager.get_all_rule_counts()
        total_rules = sum(rule_counts.values())
        
        if total_rules == 0:
            print("📦 Initializing Redis with comprehensive rules...")
            redis_manager.initialize_rules(STATIC_RULES)
            rule_counts = redis_manager.get_all_rule_counts()
            total_rules = sum(rule_counts.values())
        
        print(f"✅ Redis connected: {total_rules} rules loaded")
        for category, count in rule_counts.items():
            if count > 0:
                print(f"   - {category}: {count} patterns")
        
        # Compile all patterns for fast matching
        all_rules = redis_manager.get_all_rules()
        for category, patterns in all_rules.items():
            if patterns:
                compiled_patterns = []
                for p in patterns:
                    try:
                        compiled_patterns.append(re.compile(p, re.IGNORECASE))
                    except re.error as regex_err:
                        print(f"⚠️  Skipping invalid regex in {category}: {p[:50]}... - {regex_err}")
                compiled_rules[category] = compiled_patterns
        
        return True
        
    except Exception as e:
        print(f"⚠️  Redis connection failed: {e}")
        print("📦 Using static fallback rules (400+ patterns)...")
        
        # Use static rules as fallback
        total_rules = 0
        for category, patterns in STATIC_RULES.items():
            if patterns:
                compiled_patterns = []
                for p in patterns:
                    try:
                        compiled_patterns.append(re.compile(p, re.IGNORECASE))
                    except re.error as regex_err:
                        print(f"⚠️  Skipping invalid regex in {category}: {p[:50]}... - {regex_err}")
                compiled_rules[category] = compiled_patterns
                total_rules += len(compiled_patterns)
                print(f"   - {category}: {len(compiled_patterns)} patterns")
        
        print(f"✅ Static rules loaded: {total_rules} total patterns")
        return False

def check_rule_based_threats(request_dict: dict) -> tuple:
    """Check for known attack patterns using comprehensive Redis/static rules (400+) with context awareness"""
    try:
        method = str(request_dict.get('method', 'GET')).upper()
        path = str(request_dict.get('path', '')).lower()
        query_dict = request_dict.get('query', {})
        headers = request_dict.get('headers', {})
        content_type = headers.get('content-type', '').lower() if isinstance(headers, dict) else ''
        
        # Handle query params - support both dict and string formats
        if isinstance(query_dict, dict):
            # Build query string from dict, handling lists
            query_parts = []
            for k, v in query_dict.items():
                if isinstance(v, list):
                    for item in v:
                        query_parts.append(f"{k}={item}")
                else:
                    query_parts.append(f"{k}={v}")
            query = ' '.join(query_parts).lower()
        else:
            query = str(query_dict).lower()
            
        body = str(request_dict.get('body', '')).lower()
    except Exception:
        method = 'GET'
        path = str(request_dict.get('path', '')).lower()
        query = str(request_dict.get('query', '')).lower()
        body = str(request_dict.get('body', '')).lower()
        content_type = ''

    # Also check raw query values for CRLF and other attacks
    raw_query_values = ' '.join(str(v) for v in request_dict.get('query', {}).values() if v).lower()
    
    # Build inspection text based on context
    # For form submissions (POST with form data), skip body inspection for password/sensitive patterns
    is_form_submission = (method == 'POST' and 'application/x-www-form-urlencoded' in content_type)
    is_login_path = any(x in path for x in ['login', 'auth', 'signin', 'setup'])
    
    # Primary inspection: path + query
    full_text = f"{path} {query} {raw_query_values}"
    
    # Add body only if not a form login (to avoid false positives on password fields)
    if not (is_form_submission and is_login_path):
        full_text += f" {body}"
    
    matched_patterns = []
    
    # DEBUG: Check if rules are loaded
    if not compiled_rules:
        print(f"🚨 WARNING: compiled_rules is EMPTY! Rules not loaded!")
        return False, '', []
    
    # Category mapping for threat labels
    threat_labels = {
        'sqli_patterns': 'SQL Injection',
        'sql_patterns': 'SQL Injection',
        'xss_patterns': 'XSS',
        'path_traversal_patterns': 'Path Traversal',
        'suspicious_paths': 'Path Traversal',
        'cmd_injection_patterns': 'Command Injection',
        'cmd_patterns': 'Command Injection',
        'ldap_injection_patterns': 'LDAP Injection',
        'xxe_patterns': 'XXE',
        'ssrf_patterns': 'SSRF',
        'rfi_patterns': 'RFI',
        'lfi_patterns': 'LFI',
        'nosql_injection_patterns': 'NoSQL Injection',
        'crlf_injection_patterns': 'CRLF Injection',
        'template_injection_patterns': 'Template Injection',
        'deserialization_patterns': 'Deserialization',
        'hpp_patterns': 'HPP',
        'sensitive_data_patterns': 'Sensitive Data Exposure',
        'shellshock_patterns': 'Shellshock',
        'webshell_patterns': 'Webshell',
        'auth_bypass_patterns': 'Auth Bypass',
        'blocked_user_agents': 'Blocked User-Agent',
        'suspicious_extensions': 'Suspicious Extension',
        'encoding_patterns': 'Encoding Evasion',
    }
    
    # Categories to skip for form login requests (reduces false positives)
    skip_for_login = {'sensitive_data_patterns', 'auth_bypass_patterns', 'blocked_user_agents'} if (is_form_submission and is_login_path) else set()
    
    # Check all rule categories
    for category, patterns in compiled_rules.items():
        # Skip certain categories for legitimate login forms
        if category in skip_for_login:
            continue
            
        threat_label = threat_labels.get(category, category.replace('_', ' ').title())
        for patt in patterns:
            try:
                if patt.search(full_text):
                    matched_patterns.append((threat_label, patt.pattern[:100]))  # Truncate long patterns
                    break  # One match per category is enough
            except Exception:
                continue  # Skip pattern on regex error
    
    if matched_patterns:
        threat_types = list(set([m[0] for m in matched_patterns]))
        return True, ', '.join(threat_types), matched_patterns

    return False, '', []

def compute_rule_confidence(matched_patterns: list) -> tuple:
    """Convert matched patterns to confidence score and risk level"""
    if not matched_patterns:
        return 0.0, "LOW"

    base_weights = {
        'Path Traversal/LFI': 80,
        'SQL Injection': 90,
        'XSS': 70,
        'Command Injection': 95,
        'Encoding Evasion': 60,
    }

    scores = []
    for t, pat in matched_patterns:
        w = base_weights.get(t, 50)
        if isinstance(pat, str) and ('%2' in pat or '\\x' in pat):
            w -= 8
        scores.append(max(0, min(100, w)))

    unique_threats = len(set([t for t, _ in matched_patterns]))
    agg = min(99.9, max(scores) + (unique_threats - 1) * 4)
    
    if agg >= 90:
        risk = "CRITICAL"
    elif agg >= 75:
        risk = "HIGH"
    elif agg >= 50:
        risk = "MEDIUM"
    else:
        risk = "LOW"
    
    return float(round(agg, 1)), risk

def hierarchical_detect(request_dict: dict):
    """Hierarchical detection: Rules first, then ML if safe"""
    class ResultObj:
        def __init__(self):
            self.is_malicious = False
            self.confidence = 0.0
            self.risk_level = "LOW"
            self.reconstruction_loss = 0.0
            self.anomaly_score = 0.0
            self.detection_method = "NONE"
            self.threat_type = "None"
            self.matched_patterns = []
            # Add detailed processing info
            self.normalized_request = None
            self.text_sequence = None
            self.token_count = 0
            self.processing_details = {}
            self.inference_time_ms = 0.0

    res = ResultObj()
    
    # Store normalized request
    res.normalized_request = request_dict
    
    # Generate text sequence (same format as ParsedRequest.to_text_sequence)
    parts = [f"METHOD:{request_dict.get('method', 'GET')}"]
    
    path = request_dict.get('path', '/')
    parts.append(f"PATH:{path}")
    
    query = request_dict.get('query', {})
    if query:
        query_str = " ".join([f"{k}={v}" for k, v in query.items()])
        parts.append(f"QUERY:{query_str}")
    
    body = request_dict.get('body')
    if body:
        parts.append(f"BODY:{body}")
    
    headers = request_dict.get('headers', {})
    content_type = headers.get('Content-Type') or headers.get('content-type')
    if content_type:
        parts.append(f"CONTENT_TYPE:{content_type}")
    
    res.text_sequence = " ".join(parts)
    
    # Rule-based check first
    rule_start = time.time()
    rule_triggered, threat_type, matched_patterns = check_rule_based_threats(request_dict)
    rule_time_ms = (time.time() - rule_start) * 1000
    
    if rule_triggered:
        conf, risk = compute_rule_confidence(matched_patterns)
        res.is_malicious = True
        res.confidence = conf
        res.risk_level = risk
        res.detection_method = "RULE"
        res.threat_type = threat_type
        res.matched_patterns = matched_patterns
        res.inference_time_ms = rule_time_ms
        res.processing_details['rule_check'] = {
            'patterns_matched': len(matched_patterns),
            'threat_categories': list(set([m[0] if isinstance(m, tuple) else str(m).split(':')[0] for m in matched_patterns[:5]])),
            'inference_time_ms': rule_time_ms
        }
        return res
    
    # ML detection if rules don't flag
    if detector is not None:
        ml_start = time.time()
        ml_result = detector.detect(request_dict)
        ml_time_ms = (time.time() - ml_start) * 1000
        res.is_malicious = ml_result.is_malicious
        res.confidence = ml_result.confidence
        res.risk_level = ml_result.risk_level
        res.reconstruction_loss = ml_result.reconstruction_loss
        res.anomaly_score = ml_result.anomaly_score
        res.detection_method = "ML"
        res.threat_type = "Anomaly" if ml_result.is_malicious else "None"
        res.inference_time_ms = ml_time_ms
        
        # Add ML processing details
        res.processing_details['ml_detection'] = {
            'inference_time_ms': ml_time_ms,
            'reconstruction_loss': float(ml_result.reconstruction_loss),
            'anomaly_score': float(ml_result.anomaly_score),
            'model': 'DeBERTa-v3-small'
        }
    
    # If benign, add to incremental training collection
    if not res.is_malicious and incremental_manager is not None:
        try:
            incremental_manager.add_benign_log(request_dict)
        except Exception as e:
            print(f"⚠️  Failed to add benign log: {e}")
    
    # If malicious (detected by ML), add to attack logs for signature extraction
    if res.is_malicious and res.detection_method == "ML" and signature_manager is not None:
        try:
            signature_manager.add_attack_log(request_dict, res)
        except Exception as e:
            print(f"⚠️  Failed to add attack log: {e}")
    
    return res

# ============================================================================
# LOG PARSER
# ============================================================================

class NginxLogParser:
    """Parser for nginx logs"""
    
    def __init__(self):
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
        """Parse a single nginx log line"""
        match = self.log_pattern.match(line.strip())
        if not match:
            return None
        
        data = match.groupdict()
        
        try:
            parsed_uri = urlparse(data['request_uri'])
            path = parsed_uri.path
            query_params = parse_qs(parsed_uri.query) if parsed_uri.query else {}
            
            if data['query_string']:
                additional_params = parse_qs(data['query_string'])
                query_params.update(additional_params)
        except Exception:
            path = data['request_uri']
            query_params = {}
        
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
        
        return request

# ============================================================================
# LOG MONITORING
# ============================================================================

class LogTailer:
    """Tails a log file"""
    
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.file = None
        
    def __enter__(self):
        while not os.path.exists(self.filepath):
            time.sleep(0.1)
        
        self.file = open(self.filepath, 'r')
        self.file.seek(0, 2)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.file:
            self.file.close()
    
    def tail(self):
        """Generator that yields new lines"""
        while monitoring_active:
            line = self.file.readline()
            if line:
                yield line
            else:
                time.sleep(0.1)

def monitor_log_file(app_name: str, log_file: str):
    """Monitor a single log file"""
    parser = NginxLogParser()
    
    print(f"🔍 Starting monitoring for {app_name} at {log_file}")
    
    try:
        # Check if file exists
        if not os.path.exists(log_file):
            print(f"⚠️ Log file not found: {log_file}")
            return
            
        with LogTailer(log_file) as tailer:
            print(f"✅ Tailing {app_name} log file...")
            for line in tailer.tail():
                if not monitoring_active:
                    print(f"🛑 Stopping monitoring for {app_name}")
                    break
                
                parsed = parser.parse_line(line)
                if not parsed:
                    continue
                
                # Format request for detection (same format as in realtime_waf_monitor.py)
                request_dict = {
                    'method': parsed.get('method', 'GET'),
                    'path': parsed.get('path', '/'),
                    'query': parsed.get('query', {}),
                    'headers': parsed.get('headers', {}),
                    'body': parsed.get('body', None),
                }
                
                # Hierarchical detection: Redis rules first, then ML
                result = hierarchical_detect(request_dict)
                
                # Store result
                result_entry = {
                    'timestamp': datetime.now().isoformat(),
                    'app': app_name,
                    'method': parsed['method'],
                    'path': parsed['path'],
                    'is_malicious': result.is_malicious,
                    'confidence': result.confidence,
                    'risk_level': result.risk_level,
                    'detection_method': result.detection_method,
                    'threat_type': result.threat_type,
                    'inference_time_ms': result.inference_time_ms if hasattr(result, 'inference_time_ms') else 0.0,
                }
                log_monitor_results.append(result_entry)
                
                # Print to console for debugging
                status = "🚨 ATTACK" if result.is_malicious else "✅ BENIGN"
                print(f"{status} [{app_name}] {parsed['method']} {parsed['path'][:50]} - {result.detection_method} ({result.confidence:.1f}%)")
                
    except Exception as e:
        print(f"❌ Error monitoring {app_name}: {e}")
        import traceback
        traceback.print_exc()

def start_monitoring():
    """Start monitoring all log files"""
    global monitoring_active, monitoring_threads
    
    if monitoring_active:
        print("⚠️ Monitoring already active")
        return
    
    print("🚀 Starting live log monitoring...")
    print(f"📊 Redis rules loaded: {len(compiled_rules)} categories")
    print(f"🤖 ML detector available: {'Yes' if detector else 'No'}")
    
    monitoring_active = True
    monitoring_threads = []
    
    for app_name, log_file in LOG_FILES.items():
        thread = threading.Thread(target=monitor_log_file, args=(app_name, log_file), daemon=True)
        thread.start()
        monitoring_threads.append(thread)
    
    print(f"✅ Monitoring {len(monitoring_threads)} log files")

def stop_monitoring():
    """Stop monitoring"""
    global monitoring_active
    print("🛑 Stopping log monitoring...")
    monitoring_active = False

# ============================================================================
# CURL TESTING
# ============================================================================

def parse_curl_command(curl_cmd: str) -> Dict:
    """Parse a curl command into request components"""
    # Extract URL
    url_match = re.search(r'(?:curl\s+)?["\']?(https?://[^\s"\']+)["\']?', curl_cmd)
    if not url_match:
        return None
    
    url = url_match.group(1)
    parsed = urlparse(url)
    
    # Extract method
    method_match = re.search(r'-X\s+(\w+)', curl_cmd)
    method = method_match.group(1) if method_match else 'GET'
    
    # Extract headers
    headers = {}
    header_matches = re.finditer(r'-H\s+["\']([^:]+):\s*([^"\']+)["\']', curl_cmd)
    for match in header_matches:
        headers[match.group(1)] = match.group(2)
    
    # Extract body
    body = None
    body_match = re.search(r'-d\s+["\'](.+?)["\']', curl_cmd)
    if body_match:
        body = body_match.group(1)
        # Auto-set Content-Type for -d flag if not explicitly provided
        if 'Content-Type' not in headers and 'content-type' not in headers:
            headers['content-type'] = 'application/x-www-form-urlencoded'
    
    # Parse query
    query_params = parse_qs(parsed.query) if parsed.query else {}
    
    return {
        'method': method,
        'path': parsed.path or '/',
        'query': {k: v[0] if len(v) == 1 else v for k, v in query_params.items()},
        'headers': headers,
        'body': body,
    }

def execute_curl_test(curl_cmd: str, target_url: str = "http://localhost:8080") -> Dict:
    """Execute curl command and analyze with hierarchical WAF"""
    # Parse curl command
    request_dict = parse_curl_command(curl_cmd)
    
    if not request_dict:
        return {'error': 'Failed to parse curl command'}
    
    # DEBUG: Show what we're checking
    print(f"\n{'='*60}")
    print(f"🔍 TESTING CURL COMMAND")
    print(f"{'='*60}")
    print(f"Request Dict: {request_dict}")
    print(f"{'='*60}\n")
    
    # Run hierarchical detection
    result = hierarchical_detect(request_dict)
    
    # Try to execute actual curl
    try:
        exec_result = subprocess.run(
            curl_cmd.split(),
            capture_output=True,
            text=True,
            timeout=5
        )
        response_code = exec_result.returncode
        response_output = exec_result.stdout
    except Exception as e:
        response_code = -1
        response_output = str(e)
    
    test_result = {
        'timestamp': datetime.now().isoformat(),
        'curl_command': curl_cmd,
        'request': request_dict,
        'waf_result': {
            'is_malicious': result.is_malicious,
            'confidence': result.confidence,
            'risk_level': result.risk_level,
            'detection_method': result.detection_method,
            'threat_type': result.threat_type,
            'anomaly_score': result.anomaly_score,
            'matched_patterns': result.matched_patterns[:5] if hasattr(result, 'matched_patterns') else [],
            'inference_time_ms': result.inference_time_ms if hasattr(result, 'inference_time_ms') else 0.0,
        },
        'processing': {
            'normalized_request': result.normalized_request if hasattr(result, 'normalized_request') else request_dict,
            'text_sequence': result.text_sequence if hasattr(result, 'text_sequence') else '',
            'token_count': result.token_count if hasattr(result, 'token_count') else 0,
            'details': result.processing_details if hasattr(result, 'processing_details') else {}
        },
        'execution': {
            'return_code': response_code,
            'output': response_output[:500],  # Truncate
        }
    }
    
    test_results.append(test_result)
    return test_result

# ============================================================================
# WEB UI (HTML)
# ============================================================================

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>ISRO WAF Security Platform</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --isro-orange: #FF6B35;
            --isro-deep-orange: #E8500E;
            --isro-navy: #0D1B2A;
            --isro-blue: #1B3A5F;
            --isro-light-blue: #2E5984;
            --isro-accent: #FFB800;
            --text-dark: #1a1a1a;
            --text-light: #f5f5f5;
            --bg-light: #F8F9FA;
            --border-light: #E1E8ED;
            --success: #00C853;
            --danger: #FF3D00;
            --warning: #FFB800;
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body { 
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; 
            background: var(--isro-navy);
            color: var(--text-dark);
            min-height: 100vh;
            line-height: 1.6;
        }
        
        .container { 
            max-width: 1920px; 
            margin: 0 auto; 
            background: #ffffff;
            min-height: 100vh;
        }
        
        .header {
            background: linear-gradient(135deg, var(--isro-navy) 0%, var(--isro-blue) 100%);
            color: var(--text-light);
            padding: 24px 48px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            box-shadow: 0 4px 24px rgba(0,0,0,0.15);
            position: sticky;
            top: 0;
            z-index: 100;
        }
        
        .header-left {
            display: flex;
            align-items: center;
            gap: 20px;
        }
        
        .isro-logo {
            width: 80px;
            height: 80px;
            object-fit: contain;
        }
        
        .header-title h1 { 
            font-size: 28px;
            font-weight: 700;
            letter-spacing: -0.5px;
            margin-bottom: 4px;
        }
        
        .header-title p { 
            font-size: 13px;
            opacity: 0.85;
            font-weight: 400;
            letter-spacing: 0.3px;
        }
        
        .header-right {
            display: flex;
            align-items: center;
            gap: 16px;
        }
        
        .status-indicator {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 8px 16px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 20px;
            font-size: 13px;
            font-weight: 500;
        }
        
        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--success);
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.7; transform: scale(1.1); }
        }
        
        .tabs {
            display: flex;
            background: var(--bg-light);
            border-bottom: 2px solid var(--border-light);
            padding: 0 32px;
            gap: 4px;
        }
        
        .tab {
            flex: 1;
            max-width: 220px;
            padding: 18px 24px;
            text-align: center;
            cursor: pointer;
            font-weight: 600;
            font-size: 14px;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            border: none;
            background: transparent;
            color: var(--text-dark);
            opacity: 0.6;
            position: relative;
            border-radius: 8px 8px 0 0;
        }
        
        .tab:hover { 
            opacity: 1;
            background: rgba(255, 107, 53, 0.08);
        }
        
        .tab.active { 
            background: white;
            opacity: 1;
            color: var(--isro-orange);
            box-shadow: 0 -2px 8px rgba(0,0,0,0.05);
        }
        
        .tab.active::after {
            content: '';
            position: absolute;
            bottom: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, var(--isro-orange), var(--isro-deep-orange));
        }
        
        .tab-content { 
            display: none; 
            padding: 32px 48px;
            animation: fadeIn 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            min-height: calc(100vh - 200px);
        }
        
        .tab-content.active { display: block; }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(16px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .section {
            margin-bottom: 28px;
            padding: 28px;
            background: white;
            border-radius: 16px;
            border: 1px solid var(--border-light);
            box-shadow: 0 2px 8px rgba(0,0,0,0.04);
            transition: box-shadow 0.3s;
        }
        
        .section:hover {
            box-shadow: 0 4px 16px rgba(0,0,0,0.08);
        }
        
        .section h2 { 
            margin-bottom: 20px; 
            color: var(--isro-navy);
            font-size: 20px;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .section h2::before {
            content: '';
            width: 4px;
            height: 24px;
            background: linear-gradient(180deg, var(--isro-orange), var(--isro-deep-orange));
            border-radius: 2px;
        }
        
        .input-group {
            margin-bottom: 20px;
        }
        
        .input-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: var(--isro-navy);
            font-size: 14px;
            letter-spacing: 0.2px;
        }
        
        .input-group input, .input-group textarea {
            width: 100%;
            padding: 14px 16px;
            border: 2px solid var(--border-light);
            border-radius: 10px;
            font-size: 14px;
            font-family: 'Inter', monospace;
            transition: all 0.3s;
            background: var(--bg-light);
        }
        
        .input-group input:focus, .input-group textarea:focus {
            outline: none;
            border-color: var(--isro-orange);
            background: white;
            box-shadow: 0 0 0 3px rgba(255, 107, 53, 0.1);
        }
        
        button {
            padding: 14px 32px;
            background: linear-gradient(135deg, var(--isro-orange), var(--isro-deep-orange));
            color: white;
            border: none;
            border-radius: 10px;
            cursor: pointer;
            font-size: 15px;
            font-weight: 600;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: 0 4px 12px rgba(255, 107, 53, 0.3);
            letter-spacing: 0.3px;
        }
        
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(255, 107, 53, 0.4);
        }
        
        button:active { 
            transform: translateY(0);
        }
        
        button:disabled {
            background: #9E9E9E;
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }
        
        button.secondary {
            background: var(--isro-navy);
            box-shadow: 0 4px 12px rgba(13, 27, 42, 0.3);
        }
        
        button.secondary:hover {
            background: var(--isro-blue);
            box-shadow: 0 6px 20px rgba(13, 27, 42, 0.4);
        }
        
        button.danger {
            background: linear-gradient(135deg, var(--danger), #D32F2F);
            box-shadow: 0 4px 12px rgba(255, 61, 0, 0.3);
        }
        
        button.success {
            background: linear-gradient(135deg, var(--success), #00A142);
            box-shadow: 0 4px 12px rgba(0, 200, 83, 0.3);
        }
        
        .results {
            margin-top: 20px;
            max-height: 650px;
            overflow-y: auto;
            padding-right: 8px;
        }
        
        .results::-webkit-scrollbar {
            width: 8px;
        }
        
        .results::-webkit-scrollbar-track {
            background: var(--bg-light);
            border-radius: 4px;
        }
        
        .results::-webkit-scrollbar-thumb {
            background: var(--isro-orange);
            border-radius: 4px;
        }
        
        .result-item {
            background: white;
            padding: 20px;
            margin-bottom: 12px;
            border-radius: 12px;
            border-left: 4px solid var(--border-light);
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
            transition: all 0.3s;
        }
        
        .result-item:hover {
            transform: translateX(4px);
            box-shadow: 0 4px 16px rgba(0,0,0,0.1);
        }
        
        .result-item.malicious { 
            border-left-color: var(--danger);
            background: linear-gradient(90deg, rgba(255, 61, 0, 0.05) 0%, white 100%);
        }
        
        .result-item.benign { 
            border-left-color: var(--success);
            background: linear-gradient(90deg, rgba(0, 200, 83, 0.05) 0%, white 100%);
        }
        
        .badge {
            display: inline-block;
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            margin-right: 8px;
            letter-spacing: 0.3px;
        }
        
        .badge.attack { background: var(--danger); color: white; }
        .badge.safe { background: var(--success); color: white; }
        .badge.critical { background: var(--danger); color: white; }
        .badge.high { background: var(--isro-orange); color: white; }
        .badge.medium { background: var(--warning); color: var(--text-dark); }
        .badge.low { background: var(--success); color: white; }
        .badge.rule { background: var(--isro-navy); color: white; }
        .badge.ml { background: var(--isro-blue); color: white; }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: linear-gradient(135deg, white, var(--bg-light));
            padding: 24px;
            border-radius: 16px;
            text-align: center;
            box-shadow: 0 2px 12px rgba(0,0,0,0.06);
            border: 1px solid var(--border-light);
            transition: all 0.3s;
            position: relative;
            overflow: hidden;
        }
        
        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, var(--isro-orange), var(--isro-deep-orange));
        }
        
        .stat-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 8px 24px rgba(0,0,0,0.12);
        }
        
        .stat-card h3 {
            font-size: 36px;
            font-weight: 800;
            color: var(--isro-orange);
            margin-bottom: 8px;
            letter-spacing: -1px;
        }
        
        .stat-card p {
            color: var(--isro-navy);
            font-weight: 600;
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .hit-ratio-container {
            margin-top: 30px;
        }
        
        .hit-ratio-unified-bar {
            position: relative;
            height: 80px;
            background: var(--bg-light);
            border-radius: 16px;
            overflow: hidden;
            display: flex;
            box-shadow: 0 4px 12px rgba(0,0,0,0.08);
            border: 2px solid #e5e7eb;
        }
        
        .hit-ratio-segment {
            height: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 20px;
            color: white;
            transition: all 0.6s ease;
            text-shadow: 0 2px 4px rgba(0,0,0,0.3);
            position: relative;
        }
        
        .hit-ratio-segment.rule-segment {
            background: #ef4444;
        }
        
        .hit-ratio-segment.ml-segment {
            background: #3b82f6;
        }
        
        .hit-ratio-legend {
            display: flex;
            justify-content: center;
            gap: 40px;
            margin-top: 20px;
        }
        
        .hit-ratio-legend-item {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .hit-ratio-legend-color {
            width: 24px;
            height: 24px;
            border-radius: 6px;
        }
        
        .hit-ratio-legend-color.rule-legend {
            background: #ef4444;
        }
        
        .hit-ratio-legend-color.ml-legend {
            background: #3b82f6;
        }
        
        .hit-ratio-legend-text {
            font-weight: 600;
            font-size: 14px;
            color: var(--text-secondary);
        }
        
        .hit-ratio-bar {
            position: relative;
            height: 60px;
            background: var(--bg-light);
            border-radius: 12px;
            overflow: hidden;
            display: flex;
            align-items: center;
            box-shadow: 0 2px 8px rgba(0,0,0,0.06);
        }
        
        .hit-ratio-fill {
            height: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 18px;
            color: white;
            transition: width 0.6s ease;
            text-shadow: 0 1px 2px rgba(0,0,0,0.2);
        }
        
        .hit-ratio-fill.rule-fill {
            background: linear-gradient(135deg, var(--isro-navy), #1e3a8a);
        }
        
        .hit-ratio-fill.ml-fill {
            background: linear-gradient(135deg, var(--isro-blue), #2563eb);
        }
        
        .hit-ratio-label {
            position: absolute;
            left: 0;
            right: 0;
            text-align: center;
            font-weight: 600;
            font-size: 14px;
            color: var(--text-secondary);
            z-index: 1;
            pointer-events: none;
        }
        
        .hit-ratio-comparison {
            display: flex;
            justify-content: space-around;
            margin-top: 10px;
            padding: 20px;
            background: var(--bg-light);
            border-radius: 12px;
        }
        
        .hit-ratio-stat {
            text-align: center;
        }
        
        .hit-ratio-stat h3 {
            font-size: 32px;
            font-weight: 800;
            margin: 0 0 8px 0;
        }
        
        .hit-ratio-stat h3.rule-color {
            color: var(--isro-navy);
        }
        
        .hit-ratio-stat h3.ml-color {
            color: var(--isro-blue);
        }
        
        .hit-ratio-stat p {
            font-size: 14px;
            color: var(--text-secondary);
            margin: 0;
            font-weight: 500;
        }
        
        .log-entry {
            font-family: 'Courier New', 'Monaco', monospace;
            font-size: 13px;
            padding: 16px;
            background: var(--isro-navy);
            color: #00ff41;
            border-radius: 8px;
            margin-top: 12px;
            overflow-x: auto;
            border-left: 3px solid var(--isro-orange);
        }
        
        .control-buttons {
            display: flex;
            gap: 12px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        
        .refresh-indicator {
            color: var(--success);
            font-weight: 600;
            margin-left: 12px;
            animation: pulse 2s infinite;
            font-size: 13px;
        }
        
        code {
            background: rgba(255, 107, 53, 0.1);
            padding: 3px 8px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            color: var(--isro-orange);
            font-size: 13px;
        }
        
        .examples {
            background: var(--bg-light);
            padding: 20px;
            border-radius: 12px;
            margin-top: 20px;
            border: 1px solid var(--border-light);
        }
        
        .examples h4 {
            margin-bottom: 14px;
            color: var(--isro-navy);
            font-size: 15px;
            font-weight: 600;
        }
        
        .example-item {
            padding: 12px 16px;
            background: white;
            margin: 8px 0;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            border: 1px solid var(--border-light);
        }
        
        .example-item:hover {
            background: var(--isro-orange);
            color: white;
            transform: translateX(4px);
            border-color: var(--isro-orange);
        }
        
        .login-container {
            max-width: 420px;
            margin: 60px auto;
            padding: 40px;
            background: white;
            border-radius: 20px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.12);
            border: 1px solid var(--border-light);
        }
        
        .login-container h3 {
            text-align: center;
            color: var(--isro-navy);
            margin-bottom: 32px;
            font-size: 24px;
            font-weight: 700;
        }
        
        .signature-item {
            background: white;
            padding: 18px;
            margin: 12px 0;
            border-radius: 12px;
            border-left: 4px solid var(--isro-orange);
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
            transition: all 0.3s;
        }
        
        .signature-item:hover {
            transform: translateX(4px);
            box-shadow: 0 4px 16px rgba(0,0,0,0.1);
        }
        
        .signature-item input[type="checkbox"] {
            margin-right: 12px;
            width: 20px;
            height: 20px;
            cursor: pointer;
            accent-color: var(--isro-orange);
        }
        
        .signature-pattern {
            font-family: 'Courier New', monospace;
            background: var(--bg-light);
            padding: 10px;
            margin-top: 10px;
            border-radius: 6px;
            font-size: 13px;
            word-break: break-all;
            border-left: 2px solid var(--isro-orange);
        }
        
        .category-header {
            background: linear-gradient(135deg, var(--isro-navy), var(--isro-blue));
            color: white;
            padding: 14px 20px;
            border-radius: 10px;
            margin: 24px 0 12px 0;
            font-weight: 700;
            font-size: 14px;
            letter-spacing: 0.5px;
            text-transform: uppercase;
        }
        
        /* Pipeline Visualization Styles */
        .pipeline-container {
            background: var(--bg-light);
            padding: 32px;
            border-radius: 16px;
            margin: 24px 0;
            border: 1px solid var(--border-light);
        }
        
        .pipeline-step {
            background: white;
            border: 2px solid var(--border-light);
            border-radius: 12px;
            padding: 24px;
            margin: 16px 0;
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
        }
        
        .pipeline-step.processing {
            border-color: var(--isro-orange);
            background: linear-gradient(135deg, rgba(255, 107, 53, 0.05), white);
            box-shadow: 0 0 30px rgba(255, 107, 53, 0.2);
            transform: scale(1.02);
        }
        
        .pipeline-step.completed {
            border-color: var(--success);
            background: linear-gradient(135deg, rgba(0, 200, 83, 0.05), white);
        }
        
        .pipeline-step.failed, .pipeline-step.blocked {
            border-color: var(--danger);
            background: linear-gradient(135deg, rgba(255, 61, 0, 0.05), white);
            box-shadow: 0 0 30px rgba(255, 61, 0, 0.2);
        }
        
        .step-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 14px;
        }
        
        .step-number {
            background: linear-gradient(135deg, var(--isro-orange), var(--isro-deep-orange));
            color: white;
            width: 40px;
            height: 40px;
            border-radius: 50%;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            font-weight: 800;
            font-size: 16px;
            margin-right: 14px;
            box-shadow: 0 4px 12px rgba(255, 107, 53, 0.3);
        }
        
        .step-title {
            flex: 1;
            font-size: 16px;
            font-weight: 700;
            color: var(--isro-navy);
            letter-spacing: 0.2px;
        }
        
        .step-time {
            font-family: 'Courier New', monospace;
            font-weight: 700;
            color: var(--isro-orange);
            font-size: 14px;
            background: rgba(255, 107, 53, 0.1);
            padding: 6px 14px;
            border-radius: 20px;
            border: 2px solid var(--isro-orange);
        }
        
        .step-status {
            font-weight: 600;
            padding: 10px 16px;
            border-radius: 8px;
            margin: 12px 0;
            display: inline-block;
            font-size: 14px;
        }
        
        .step-status.waiting {
            background: var(--bg-light);
            color: #666;
        }
        
        .step-status.processing {
            background: var(--isro-orange);
            color: white;
            animation: pulse 1.5s infinite;
        }
        
        .step-status.success {
            background: var(--success);
            color: white;
        }
        
        .step-status.blocked {
            background: var(--danger);
            color: white;
        }
        
        .step-status.skipped {
            background: var(--warning);
            color: var(--text-dark);
        }
        
        .step-details {
            background: var(--bg-light);
            padding: 16px;
            border-radius: 8px;
            margin-top: 12px;
            font-size: 13px;
            max-height: 250px;
            overflow-y: auto;
            border-left: 3px solid var(--isro-orange);
        }
        
        .step-details pre {
            margin: 0;
            white-space: pre-wrap;
            word-break: break-all;
            font-family: 'Courier New', monospace;
            font-size: 12px;
        }
        
        .pipeline-arrow {
            text-align: center;
            font-size: 28px;
            color: var(--isro-orange);
            margin: -8px 0;
            animation: bounce 2s infinite;
        }
        
        @keyframes bounce {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(8px); }
        }
        
        .total-time-container {
            margin-top: 32px;
            text-align: center;
        }
        
        .total-time-card {
            background: linear-gradient(135deg, var(--isro-navy), var(--isro-blue));
            color: white;
            padding: 32px;
            border-radius: 20px;
            display: inline-block;
            min-width: 350px;
            box-shadow: 0 8px 32px rgba(13, 27, 42, 0.4);
        }
        
        .total-time-card h3 {
            font-size: 42px;
            margin-bottom: 8px;
            font-weight: 800;
            letter-spacing: -1px;
        }
        
        .total-time-card p {
            font-size: 14px;
            opacity: 0.9;
            font-weight: 500;
            letter-spacing: 0.5px;
            text-transform: uppercase;
        }
        
        .detail-row {
            display: flex;
            justify-content: space-between;
            margin: 8px 0;
            padding: 8px 0;
            border-bottom: 1px solid var(--border-light);
        }
        
        .detail-label {
            font-weight: 700;
            color: var(--isro-navy);
            font-size: 13px;
        }
        
        .detail-value {
            color: var(--isro-orange);
            font-family: 'Courier New', monospace;
            font-size: 13px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-left">
                <img src="isro_logo.jpg" alt="ISRO Logo" class="isro-logo">
                <div class="header-title">
                    <h1>ISRO WAF Security Platform</h1>
                    <p>400+ Redis Rules → ML Detection | Real-time Log Analysis | Advanced Threat Protection</p>
                </div>
            </div>
            <div class="header-right">
                <div class="status-indicator">
                    <span class="status-dot"></span>
                    <span>System Online</span>
                </div>
            </div>
        </div>
        
        <div class="tabs">
            <button class="tab active" onclick="showTab('testing')">🧪 Live Testing</button>
            <button class="tab" onclick="showTab('monitoring')">📊 Log Monitoring</button>
            <button class="tab" onclick="showTab('stats')">📈 Statistics</button>
            <button class="tab" onclick="showTab('incremental')">🔄 Incremental Training</button>
            <button class="tab" onclick="showTab('admin')">🔐 Admin</button>
        </div>
        
        <div id="testing" class="tab-content active">
            <div class="section">
                <h2>Live curl Testing with Pipeline Visualization</h2>
                <div class="input-group">
                    <label>Enter curl command:</label>
                    <textarea id="curlInput" rows="3" placeholder='curl "http://localhost:8080/test?id=1 OR 1=1"'></textarea>
                </div>
                <button onclick="testCurl()" id="testButton">🚀 Test Request</button>
                
                <div class="examples">
                    <h4>📋 Example Payloads:</h4>
                    <div class="example-item" onclick="document.getElementById('curlInput').value = this.innerText">curl "http://localhost:8080/login?user=admin&pass=test123"</div>
                    <div class="example-item" onclick="document.getElementById('curlInput').value = this.innerText">curl "http://localhost:8080/file?path=../../etc/passwd"</div>
                    <div class="example-item" onclick="document.getElementById('curlInput').value = this.innerText">curl "http://localhost:8080/api/users?id=1; DROP TABLE users--"</div>
                    <div class="example-item" onclick="document.getElementById('curlInput').value = this.innerText">curl "http://localhost:8080/page?name=&lt;script&gt;alert('XSS')&lt;/script&gt;"</div>
                </div>
            </div>
            
            <!-- Processing Pipeline Visualization -->
            <div id="pipelineSection" class="section" style="display: none;">
                <h2>🔄 Processing Pipeline</h2>
                <div class="pipeline-container">
                    <div class="pipeline-step" id="step1">
                        <div class="step-header">
                            <span class="step-number">1</span>
                            <span class="step-title">Curl Parsing</span>
                            <span class="step-time" id="time1">⏱️ 0ms</span>
                        </div>
                        <div class="step-status" id="status1">⏳ Waiting...</div>
                        <div class="step-details" id="details1"></div>
                    </div>
                    
                    <div class="pipeline-arrow">↓</div>
                    
                    <div class="pipeline-step" id="step2">
                        <div class="step-header">
                            <span class="step-number">2</span>
                            <span class="step-title">Request Normalization</span>
                            <span class="step-time" id="time2">⏱️ 0ms</span>
                        </div>
                        <div class="step-status" id="status2">⏳ Waiting...</div>
                        <div class="step-details" id="details2"></div>
                    </div>
                    
                    <div class="pipeline-arrow">↓</div>
                    
                    <div class="pipeline-step" id="step3">
                        <div class="step-header">
                            <span class="step-number">3</span>
                            <span class="step-title">Redis Rule Check</span>
                            <span class="step-time" id="time3">⏱️ 0ms</span>
                        </div>
                        <div class="step-status" id="status3">⏳ Waiting...</div>
                        <div class="step-details" id="details3"></div>
                    </div>
                    
                    <div class="pipeline-arrow">↓</div>
                    
                    <div class="pipeline-step" id="step4">
                        <div class="step-header">
                            <span class="step-number">4</span>
                            <span class="step-title">Text Sequence Generation</span>
                            <span class="step-time" id="time4">⏱️ 0ms</span>
                        </div>
                        <div class="step-status" id="status4">⏳ Waiting...</div>
                        <div class="step-details" id="details4"></div>
                    </div>
                    
                    <div class="pipeline-arrow">↓</div>
                    
                    <div class="pipeline-step" id="step5">
                        <div class="step-header">
                            <span class="step-number">5</span>
                            <span class="step-title">Tokenization</span>
                            <span class="step-time" id="time5">⏱️ 0ms</span>
                        </div>
                        <div class="step-status" id="status5">⏳ Waiting...</div>
                        <div class="step-details" id="details5"></div>
                    </div>
                    
                    <div class="pipeline-arrow">↓</div>
                    
                    <div class="pipeline-step" id="step6">
                        <div class="step-header">
                            <span class="step-number">6</span>
                            <span class="step-title">ML Model Detection</span>
                            <span class="step-time" id="time6">⏱️ 0ms</span>
                        </div>
                        <div class="step-status" id="status6">⏳ Waiting...</div>
                        <div class="step-details" id="details6"></div>
                    </div>
                    
                    <div class="pipeline-arrow">↓</div>
                    
                    <div class="pipeline-step" id="step7">
                        <div class="step-header">
                            <span class="step-number">7</span>
                            <span class="step-title">Final Decision</span>
                            <span class="step-time" id="time7">⏱️ 0ms</span>
                        </div>
                        <div class="step-status" id="status7">⏳ Waiting...</div>
                        <div class="step-details" id="details7"></div>
                    </div>
                </div>
                
                <div class="total-time-container">
                    <div class="total-time-card">
                        <h3 id="totalTime">⚡ Total: 0ms</h3>
                        <p>End-to-End Processing Time</p>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2>📊 Test Results</h2>
                <div id="testResults" class="results"></div>
            </div>
        </div>
        
        <div id="monitoring" class="tab-content">
            <div class="section">
                <h2>Log Monitoring Control</h2>
                <div class="control-buttons">
                    <button onclick="startMonitoring()">▶️ Start Monitoring</button>
                    <button onclick="stopMonitoring()">⏹️ Stop Monitoring</button>
                    <span id="monitorStatus"></span>
                </div>
                <p style="color: #6c757d; margin-top: 10px;">
                    Monitoring: <strong>DVWA</strong>, <strong>Juice Shop</strong>, <strong>WebGoat</strong>
                </p>
            </div>
            
            <div class="section">
                <h2>Live Log Feed <span id="autoRefresh" class="refresh-indicator">● Auto-refreshing</span></h2>
                <div id="logResults" class="results"></div>
            </div>
        </div>
        
        <div id="stats" class="tab-content">
            <div class="section">
                <h2>Overall Statistics</h2>
                <div class="stats" id="statsCards"></div>
            </div>
            
            <div class="section">
                <h2>Detection Methods Distribution</h2>
                <div id="methodStats"></div>
            </div>
            
            <div class="section">
                <h2>Hit Ratio: Rule vs ML Detection</h2>
                <div id="hitRatioStats"></div>
            </div>
            
            <div class="section">
                <h2>Mean Inference Time (ms)</h2>
                <div id="inferenceTimeStats"></div>
            </div>
            
            <div class="section">
                <h2>Recent Detections</h2>
                <div id="recentDetections" class="results"></div>
            </div>
        </div>
        
        <div id="incremental" class="tab-content">
            <div class="section">
                <h2>Incremental Training Status</h2>
                <div class="stats" id="incrementalStats"></div>
            </div>
            
            <div class="section">
                <h2>Configuration</h2>
                <div class="input-group">
                    <label>Trigger Threshold (number of benign logs):</label>
                    <input type="number" id="triggerCount" placeholder="200" min="10" value="200">
                </div>
                <div class="control-buttons">
                    <button onclick="updateTriggerCount()">💾 Update Threshold</button>
                    <button onclick="triggerTraining()" style="background: #28a745;">🚀 Trigger Training Now</button>
                    <button onclick="clearLogs()" style="background: #dc3545;">🗑️ Clear Logs</button>
                </div>
            </div>
            
            <div class="section">
                <h2>Training History</h2>
                <div id="trainingHistory" class="results"></div>
            </div>
            
            <div class="section" style="background: #f8f9fa; padding: 15px; border-radius: 8px;">
                <h3 style="margin-bottom: 10px; color: #667eea;">ℹ️ How It Works</h3>
                <p style="margin-bottom: 8px;">• <strong>Automatic Collection:</strong> Benign requests (classified by Rules or ML) are automatically saved to <code>new_benign_logs.json</code></p>
                <p style="margin-bottom: 8px;">• <strong>Auto Training:</strong> When the threshold is reached (default: 200 logs), incremental training starts automatically</p>
                <p style="margin-bottom: 8px;">• <strong>Simple Fine-Tuning:</strong> The model continues MLM training on new benign data without forgetting old patterns</p>
                <p style="margin-bottom: 8px;">• <strong>No Downtime:</strong> Training runs in the background - the WAF continues to work normally</p>
                <p>• <strong>Archive:</strong> After training, logs are archived with a timestamp for audit purposes</p>
            </div>
        </div>
        
        <div id="admin" class="tab-content">
            <!-- Login Screen -->
            <div id="adminLogin" class="login-container">
                <h3>🔐 Admin Login</h3>
                <div class="input-group">
                    <label>Username:</label>
                    <input type="text" id="adminUsername" placeholder="admin">
                </div>
                <div class="input-group">
                    <label>Password:</label>
                    <input type="password" id="adminPassword" placeholder="password">
                </div>
                <button onclick="adminLogin()" style="width: 100%;">🔓 Login</button>
            </div>
            
            <!-- Admin Panel (hidden until login) -->
            <div id="adminPanel" style="display: none;">
                <div class="section">
                    <h2>Signature Management <button onclick="adminLogout()" style="float: right; background: #dc3545;">🚪 Logout</button></h2>
                    <div class="stats" id="signatureStats"></div>
                </div>
                
                <div class="section">
                    <h2>Pending Signatures</h2>
                    <p style="color: #6c757d; margin-bottom: 15px;">
                        Review and approve signatures extracted from ML-detected attacks. Selected signatures will be added to Redis rules.
                    </p>
                    <div class="control-buttons">
                        <button onclick="loadSignatures()">🔄 Refresh Signatures</button>
                        <button onclick="approveSelected()" style="background: #28a745;">✅ Approve Selected</button>
                        <button onclick="clearAttackLogs()" style="background: #dc3545;">🗑️ Clear Attack Logs</button>
                    </div>
                    <div id="signatureList" class="results"></div>
                </div>
                
                <div class="section">
                    <h2>Attack Log Statistics</h2>
                    <div id="attackStats"></div>
                </div>
                
                <div class="section" style="background: #f8f9fa; padding: 15px; border-radius: 8px;">
                    <h3 style="margin-bottom: 10px; color: #667eea;">ℹ️ How It Works</h3>
                    <p style="margin-bottom: 8px;">• <strong>ML Detection:</strong> When the ML model detects an attack, it's automatically saved to <code>new_attack_logs.json</code></p>
                    <p style="margin-bottom: 8px;">• <strong>Pattern Extraction:</strong> The system analyzes attack logs and extracts signature patterns</p>
                    <p style="margin-bottom: 8px;">• <strong>Admin Review:</strong> You can review extracted signatures and select which ones to add to Redis</p>
                    <p style="margin-bottom: 8px;">• <strong>Redis Update:</strong> Approved signatures are pushed to Redis, enhancing rule-based detection</p>
                    <p>• <strong>Continuous Improvement:</strong> This creates a feedback loop where ML detections improve rule-based detection</p>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        let autoRefreshInterval = null;
        
        function showTab(tabName) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            
            event.target.classList.add('active');
            document.getElementById(tabName).classList.add('active');
            
            if (tabName === 'monitoring') {
                startAutoRefresh();
            } else if (tabName === 'stats') {
                loadStats();
                stopAutoRefresh();
            } else if (tabName === 'incremental') {
                loadIncrementalStats();
                stopAutoRefresh();
            } else {
                stopAutoRefresh();
            }
        }
        
        async function testCurl() {
            const curlCmd = document.getElementById('curlInput').value;
            if (!curlCmd) {
                alert('Please enter a curl command');
                return;
            }
            
            // Show pipeline section
            document.getElementById('pipelineSection').style.display = 'block';
            
            // Disable test button
            const testButton = document.getElementById('testButton');
            testButton.disabled = true;
            testButton.innerText = '⏳ Processing...';
            
            // Reset all steps
            resetPipeline();
            
            try {
                // Simulate step-by-step processing with timing
                let startTime = Date.now();
                let stepStartTime = startTime;
                
                // Step 1: Curl Parsing
                updateStep(1, 'processing', '🔄 Parsing curl command...');
                await sleep(100);
                updateStep(1, 'success', '✅ Curl command parsed successfully');
                updateStepTime(1, Date.now() - stepStartTime);
                updateStepDetails(1, `<div class="detail-row"><span class="detail-label">Command:</span><span class="detail-value">${escapeHtml(curlCmd)}</span></div>`);
                
                // Step 2: Request Normalization
                stepStartTime = Date.now();
                updateStep(2, 'processing', '🔄 Normalizing request...');
                await sleep(50);
                
                // Make actual API call
                const response = await fetch('/api/test-curl', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({curl_command: curlCmd})
                });
                
                // Check if response is OK
                if (!response.ok) {
                    const errorText = await response.text();
                    updateStep(2, 'failed', '❌ Server error');
                    updateStepDetails(2, `<div style="color: #dc3545;">HTTP ${response.status}: ${errorText.substring(0, 200)}</div>`);
                    throw new Error(`Server returned ${response.status}`);
                }
                
                // Check if response is JSON
                const contentType = response.headers.get('content-type');
                if (!contentType || !contentType.includes('application/json')) {
                    const text = await response.text();
                    updateStep(2, 'failed', '❌ Invalid response');
                    updateStepDetails(2, `<div style="color: #dc3545;">Server returned HTML instead of JSON. Check server logs.</div>`);
                    throw new Error('Invalid JSON response from server');
                }
                
                const result = await response.json();
                
                // Check if request was blocked or processing error
                if (result.error) {
                    updateStep(2, 'failed', '❌ Normalization failed');
                    updateStepDetails(2, `<div style="color: #dc3545;">${result.error}</div>`);
                    throw new Error(result.error);
                }
                
                updateStep(2, 'success', '✅ Request normalized');
                updateStepTime(2, Date.now() - stepStartTime);
                if (result.processing && result.processing.normalized_request) {
                    const req = result.processing.normalized_request;
                    let normalized = `<div class="detail-row"><span class="detail-label">Method:</span><span class="detail-value">${req.method}</span></div>
                                     <div class="detail-row"><span class="detail-label">Path:</span><span class="detail-value">${req.path}</span></div>`;
                    
                    // Add query parameters
                    if (req.query && Object.keys(req.query).length > 0) {
                        const queryStr = Object.entries(req.query).map(([k, v]) => `${k}=${v}`).join(', ');
                        normalized += `<div class="detail-row"><span class="detail-label">Query:</span><span class="detail-value">${escapeHtml(queryStr)}</span></div>`;
                    }
                    
                    // Add body
                    if (req.body) {
                        normalized += `<div class="detail-row"><span class="detail-label">Body:</span><span class="detail-value">${escapeHtml(req.body)}</span></div>`;
                    }
                    
                    // Add headers
                    if (req.headers && Object.keys(req.headers).length > 0) {
                        const headersStr = Object.entries(req.headers).map(([k, v]) => `${k}: ${v}`).join('; ');
                        normalized += `<div class="detail-row"><span class="detail-label">Headers:</span><span class="detail-value">${escapeHtml(headersStr)}</span></div>`;
                    }
                    
                    updateStepDetails(2, normalized);
                } else if (result.request) {
                    const normalized = `<div class="detail-row"><span class="detail-label">Method:</span><span class="detail-value">${result.request.method}</span></div>
                                       <div class="detail-row"><span class="detail-label">Path:</span><span class="detail-value">${result.request.path}</span></div>`;
                    updateStepDetails(2, normalized);
                }
                
                // Step 3: Redis Rule Check
                stepStartTime = Date.now();
                updateStep(3, 'processing', '🔄 Checking Redis rules...');
                await sleep(80);
                
                const rulesBlocked = result.waf_result.detection_method === 'RULE';
                
                if (rulesBlocked) {
                    updateStep(3, 'blocked', '🚨 BLOCKED BY RULES');
                    updateStepTime(3, Date.now() - stepStartTime);
                    updateStepDetails(3, `<div style="color: #dc3545; font-weight: 600;">Attack detected by Redis rule patterns!</div>
                                         <div class="detail-row"><span class="detail-label">Threat Type:</span><span class="detail-value">${result.waf_result.threat_type}</span></div>
                                         <div class="detail-row"><span class="detail-label">Risk Level:</span><span class="detail-value">${result.waf_result.risk_level}</span></div>`);
                    
                    // Mark remaining steps as skipped
                    updateStep(4, 'skipped', '⊘ Skipped (Blocked by Rules)');
                    updateStep(5, 'skipped', '⊘ Skipped (Blocked by Rules)');
                    updateStep(6, 'skipped', '⊘ Skipped (Blocked by Rules)');
                    
                    // Jump to final decision
                    stepStartTime = Date.now();
                    updateStep(7, 'processing', '🔄 Generating final decision...');
                    await sleep(50);
                    updateStep(7, 'blocked', '🚨 REQUEST BLOCKED');
                    updateStepTime(7, Date.now() - stepStartTime);
                    updateStepDetails(7, `<div style="color: #dc3545; font-weight: 600; font-size: 1.1em;">REQUEST BLOCKED</div>
                                         <div class="detail-row"><span class="detail-label">Confidence:</span><span class="detail-value">${result.waf_result.confidence.toFixed(1)}%</span></div>
                                         <div class="detail-row"><span class="detail-label">Detection:</span><span class="detail-value">${result.waf_result.detection_method}</span></div>`);
                } else {
                    updateStep(3, 'success', '✅ No rule matches, proceeding to ML');
                    updateStepTime(3, Date.now() - stepStartTime);
                    updateStepDetails(3, '<div style="color: #28a745;">No malicious patterns detected in Redis rules</div>');
                    
                    // Step 4: Text Sequence Generation
                    stepStartTime = Date.now();
                    updateStep(4, 'processing', '🔄 Generating text sequence...');
                    await sleep(60);
                    updateStep(4, 'success', '✅ Text sequence generated');
                    updateStepTime(4, Date.now() - stepStartTime);
                    
                    // Display full text sequence
                    if (result.processing && result.processing.text_sequence) {
                        const textSeq = result.processing.text_sequence;
                        updateStepDetails(4, `<div style="margin-bottom: 8px;"><strong>Generated Text Sequence:</strong></div>
                                             <div style="background: #f8f9fa; padding: 10px; border-radius: 5px; font-family: 'Courier New', monospace; word-break: break-all; font-size: 0.85em; color: #667eea;">${escapeHtml(textSeq)}</div>
                                             <div class="detail-row" style="margin-top: 10px;"><span class="detail-label">Format:</span><span class="detail-value">METHOD:X PATH:Y QUERY:... BODY:... CONTENT_TYPE:...</span></div>`);
                    } else {
                        updateStepDetails(4, '<div class="detail-row"><span class="detail-label">Format:</span><span class="detail-value">METHOD:GET PATH:/test QUERY:...</span></div>');
                    }
                    
                    // Step 5: Tokenization
                    stepStartTime = Date.now();
                    updateStep(5, 'processing', '🔄 Tokenizing with DeBERTa...');
                    await sleep(100);
                    updateStep(5, 'success', '✅ Request tokenized');
                    updateStepTime(5, Date.now() - stepStartTime);
                    updateStepDetails(5, '<div class="detail-row"><span class="detail-label">Tokenizer:</span><span class="detail-value">microsoft/deberta-v3-small</span></div><div class="detail-row"><span class="detail-label">Max Length:</span><span class="detail-value">256 tokens</span></div>');
                    
                    // Step 6: ML Model Detection
                    stepStartTime = Date.now();
                    updateStep(6, 'processing', '🔄 Running ML detection...');
                    await sleep(150);
                    
                    const mlBlocked = result.waf_result.detection_method === 'ML' && result.waf_result.is_malicious;
                    
                    if (mlBlocked) {
                        updateStep(6, 'blocked', '🚨 ANOMALY DETECTED');
                        updateStepTime(6, Date.now() - stepStartTime);
                        updateStepDetails(6, `<div style="color: #dc3545; font-weight: 600;">ML model detected anomaly!</div>
                                             <div class="detail-row"><span class="detail-label">Anomaly Score:</span><span class="detail-value">${result.waf_result.anomaly_score.toFixed(4)}</span></div>
                                             <div class="detail-row"><span class="detail-label">Threat Type:</span><span class="detail-value">${result.waf_result.threat_type}</span></div>`);
                    } else {
                        updateStep(6, 'success', '✅ No anomaly detected');
                        updateStepTime(6, Date.now() - stepStartTime);
                        updateStepDetails(6, `<div style="color: #28a745;">Request appears benign</div>
                                             <div class="detail-row"><span class="detail-label">Anomaly Score:</span><span class="detail-value">${result.waf_result.anomaly_score.toFixed(4)}</span></div>`);
                    }
                    
                    // Step 7: Final Decision
                    stepStartTime = Date.now();
                    updateStep(7, 'processing', '🔄 Generating final decision...');
                    await sleep(50);
                    
                    if (result.waf_result.is_malicious) {
                        updateStep(7, 'blocked', '🚨 REQUEST BLOCKED');
                        updateStepDetails(7, `<div style="color: #dc3545; font-weight: 600; font-size: 1.1em;">REQUEST BLOCKED</div>
                                             <div class="detail-row"><span class="detail-label">Confidence:</span><span class="detail-value">${result.waf_result.confidence.toFixed(1)}%</span></div>
                                             <div class="detail-row"><span class="detail-label">Detection:</span><span class="detail-value">${result.waf_result.detection_method}</span></div>`);
                    } else {
                        updateStep(7, 'success', '✅ REQUEST ALLOWED');
                        updateStepDetails(7, `<div style="color: #28a745; font-weight: 600; font-size: 1.1em;">REQUEST ALLOWED</div>
                                             <div class="detail-row"><span class="detail-label">Confidence:</span><span class="detail-value">${result.waf_result.confidence.toFixed(1)}%</span></div>
                                             <div class="detail-row"><span class="detail-label">Risk Level:</span><span class="detail-value">${result.waf_result.risk_level}</span></div>`);
                    }
                    updateStepTime(7, Date.now() - stepStartTime);
                }
                
                // Update total time
                const totalTime = Date.now() - startTime;
                document.getElementById('totalTime').innerText = `⚡ Total: ${totalTime}ms`;
                
                // Add totalTime to result
                result.total_time_ms = totalTime;
                
                // Display result in results section
                displayTestResult(result);
                
            } catch (error) {
                console.error('Test failed:', error);
                alert('Test failed: ' + error.message);
            } finally {
                // Re-enable test button
                testButton.disabled = false;
                testButton.innerText = '🚀 Test Request';
            }
        }
        
        function resetPipeline() {
            for (let i = 1; i <= 7; i++) {
                const step = document.getElementById(`step${i}`);
                step.className = 'pipeline-step';
                updateStep(i, 'waiting', '⏳ Waiting...');
                updateStepTime(i, 0);
                updateStepDetails(i, '');
            }
            document.getElementById('totalTime').innerText = '⚡ Total: 0ms';
        }
        
        function updateStep(stepNum, status, message) {
            const statusElement = document.getElementById(`status${stepNum}`);
            const stepElement = document.getElementById(`step${stepNum}`);
            
            statusElement.innerText = message;
            statusElement.className = `step-status ${status}`;
            
            // Update step container class
            stepElement.className = 'pipeline-step';
            if (status === 'processing') {
                stepElement.classList.add('processing');
            } else if (status === 'success') {
                stepElement.classList.add('completed');
            } else if (status === 'blocked' || status === 'failed') {
                stepElement.classList.add('blocked');
            }
        }
        
        function updateStepTime(stepNum, timeMs) {
            const timeElement = document.getElementById(`time${stepNum}`);
            timeElement.innerText = `⏱️ ${timeMs}ms`;
        }
        
        function updateStepDetails(stepNum, html) {
            const detailsElement = document.getElementById(`details${stepNum}`);
            detailsElement.innerHTML = html;
        }
        
        function sleep(ms) {
            return new Promise(resolve => setTimeout(resolve, ms));
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.innerText = text;
            return div.innerHTML;
        }
        
        function displayTestResult(result) {
            const container = document.getElementById('testResults');
            const div = document.createElement('div');
            div.className = `result-item ${result.waf_result.is_malicious ? 'malicious' : 'benign'}`;
            
            div.innerHTML = `
                <div style="margin-bottom: 10px;">
                    <span class="badge ${result.waf_result.is_malicious ? 'attack' : 'safe'}">
                        ${result.waf_result.is_malicious ? '🚨 ATTACK' : '✅ SAFE'}
                    </span>
                    <span class="badge ${result.waf_result.risk_level.toLowerCase()}">
                        ${result.waf_result.risk_level}
                    </span>
                    <span class="badge ${result.waf_result.detection_method.toLowerCase()}">
                        ${result.waf_result.detection_method}
                    </span>
                    <span style="color: #6c757d;">${result.timestamp}</span>
                </div>
                <p><strong>Request:</strong> ${result.request.method} ${result.request.path}</p>
                <p><strong>Threat Type:</strong> ${result.waf_result.threat_type}</p>
                <p><strong>Confidence:</strong> ${result.waf_result.confidence.toFixed(1)}%</p>
                <p><strong>Anomaly Score:</strong> ${result.waf_result.anomaly_score.toFixed(4)}</p>
                <div class="log-entry"><code>${result.curl_command}</code></div>
                ${result.total_time_ms ? `<p style="margin-top: 8px;"><strong>⚡ Total:</strong> ${result.total_time_ms}ms<br/><small style="color: #6c757d;">End-to-End Processing Time</small></p>` : ''}
            `;
            
            container.insertBefore(div, container.firstChild);
        }
        
        async function startMonitoring() {
            const response = await fetch('/api/monitoring/start', {method: 'POST'});
            const result = await response.json();
            document.getElementById('monitorStatus').innerHTML = 
                '<span class="refresh-indicator">● Monitoring Active</span>';
            startAutoRefresh();
        }
        
        async function stopMonitoring() {
            const response = await fetch('/api/monitoring/stop', {method: 'POST'});
            const result = await response.json();
            document.getElementById('monitorStatus').innerHTML = 
                '<span style="color: #dc3545; font-weight: 600;">● Stopped</span>';
            stopAutoRefresh();
        }
        
        function startAutoRefresh() {
            if (autoRefreshInterval) return;
            loadLogResults();
            autoRefreshInterval = setInterval(loadLogResults, 2000);
        }
        
        function stopAutoRefresh() {
            if (autoRefreshInterval) {
                clearInterval(autoRefreshInterval);
                autoRefreshInterval = null;
            }
        }
        
        async function loadLogResults() {
            const response = await fetch('/api/monitoring/results');
            const data = await response.json();
            
            const container = document.getElementById('logResults');
            container.innerHTML = '';
            
            data.results.slice(0, 50).forEach(entry => {
                const div = document.createElement('div');
                div.className = `result-item ${entry.is_malicious ? 'malicious' : 'benign'}`;
                
                div.innerHTML = `
                    <div style="margin-bottom: 10px;">
                        <span class="badge ${entry.is_malicious ? 'attack' : 'safe'}">
                            ${entry.is_malicious ? '🚨' : '✅'}
                        </span>
                        <span class="badge ${entry.risk_level.toLowerCase()}">${entry.risk_level}</span>
                        <span class="badge ${entry.detection_method.toLowerCase()}">${entry.detection_method}</span>
                        <strong>${entry.app}</strong>
                        <span style="color: #6c757d; float: right;">${entry.timestamp.split('T')[1].split('.')[0]}</span>
                    </div>
                    <p><strong>${entry.method}</strong> ${entry.path}</p>
                    <p><strong>Threat:</strong> ${entry.threat_type} | <strong>Confidence:</strong> ${entry.confidence.toFixed(1)}%</p>
                `;
                
                container.appendChild(div);
            });
        }
        
        async function loadStats() {
            const response = await fetch('/api/stats');
            const data = await response.json();
            
            // Stats cards
            let statsHTML = `
                <div class="stat-card">
                    <h3>${data.total_requests}</h3>
                    <p>Total Requests</p>
                </div>
                <div class="stat-card">
                    <h3>${data.attacks_detected}</h3>
                    <p>Attacks Detected</p>
                </div>
                <div class="stat-card">
                    <h3>${data.benign_requests}</h3>
                    <p>Benign Requests</p>
                </div>
                <div class="stat-card">
                    <h3>${data.detection_rate.toFixed(1)}%</h3>
                    <p>Detection Rate</p>
                </div>
            `;
            
            // Add incremental stats if available
            if (data.incremental) {
                const inc = data.incremental;
                statsHTML += `
                    <div class="stat-card" style="border: 2px solid #667eea;">
                        <h3>${inc.current_log_count || 0}</h3>
                        <p>New Benign Logs</p>
                        <small style="color: #667eea;">${inc.progress_to_trigger || '0/200'}</small>
                    </div>
                `;
            }
            
            const statsCards = document.getElementById('statsCards');
            statsCards.innerHTML = statsHTML;
            
            // Method stats
            const methodStats = document.getElementById('methodStats');
            methodStats.innerHTML = Object.entries(data.by_method).map(([method, count]) => `
                <div class="result-item">
                    <span class="badge ${method.toLowerCase()}">${method}</span>
                    <strong>${count}</strong> detections
                </div>
            `).join('');
            
            // Hit Ratio Stats
            const ruleCount = (data.by_method['RULE'] || 0);
            const mlCount = (data.by_method['ML'] || 0);
            const totalDetections = ruleCount + mlCount;
            
            const rulePercentage = totalDetections > 0 ? (ruleCount / totalDetections * 100).toFixed(1) : 0;
            const mlPercentage = totalDetections > 0 ? (mlCount / totalDetections * 100).toFixed(1) : 0;
            
            const hitRatioStats = document.getElementById('hitRatioStats');
            hitRatioStats.innerHTML = `
                <div class="hit-ratio-comparison">
                    <div class="hit-ratio-stat">
                        <h3 class="rule-color">${ruleCount}</h3>
                        <p>🛡️ RULE DETECTIONS</p>
                    </div>
                    <div class="hit-ratio-stat">
                        <h3 style="color: var(--text-secondary);">vs</h3>
                        <p style="opacity: 0.6;">comparison</p>
                    </div>
                    <div class="hit-ratio-stat">
                        <h3 class="ml-color">${mlCount}</h3>
                        <p>🤖 ML DETECTIONS</p>
                    </div>
                </div>
                
                <div class="hit-ratio-container">
                    <div class="hit-ratio-unified-bar">
                        ${rulePercentage > 0 ? `
                            <div class="hit-ratio-segment rule-segment" style="width: ${rulePercentage}%;">
                                ${rulePercentage > 8 ? rulePercentage + '%' : ''}
                            </div>
                        ` : ''}
                        ${mlPercentage > 0 ? `
                            <div class="hit-ratio-segment ml-segment" style="width: ${mlPercentage}%;">
                                ${mlPercentage > 8 ? mlPercentage + '%' : ''}
                            </div>
                        ` : ''}
                    </div>
                    
                    <div class="hit-ratio-legend">
                        <div class="hit-ratio-legend-item">
                            <div class="hit-ratio-legend-color rule-legend"></div>
                            <div class="hit-ratio-legend-text">🛡️ RULE-BASED (${rulePercentage}%)</div>
                        </div>
                        <div class="hit-ratio-legend-item">
                            <div class="hit-ratio-legend-color ml-legend"></div>
                            <div class="hit-ratio-legend-text">🤖 ML-BASED (${mlPercentage}%)</div>
                        </div>
                    </div>
                </div>
            `;
            
            // Inference Time Stats - Column Graph with Thin Lines
            const timeSeriesData = [];
            
            data.recent.forEach((entry, index) => {
                const time = entry.total_time_ms || entry.inference_time_ms || 0;
                const method = entry.detection_method;
                if (method === 'RULE' || method === 'ML') {
                    timeSeriesData.push({
                        index: index,
                        time: time,
                        method: method,
                        timestamp: entry.timestamp
                    });
                }
            });
            
            // Calculate overall average from all hits
            const allTimes = timeSeriesData.map(d => d.time);
            const overallAvg = allTimes.length > 0 ? (allTimes.reduce((a, b) => a + b, 0) / allTimes.length).toFixed(2) : 0;
            
            // Find max time for scaling
            const maxTime = Math.max(...allTimes, parseFloat(overallAvg), 100);
            
            // Generate SVG graph
            const graphWidth = 900;
            const graphHeight = 300;
            const padding = 50;
            const plotWidth = graphWidth - 2 * padding;
            const plotHeight = graphHeight - 2 * padding;
            
            // Calculate bar width (thin lines)
            const barWidth = Math.max(2, Math.min(8, plotWidth / timeSeriesData.length));
            const spacing = plotWidth / (timeSeriesData.length || 1);
            
            // Generate thin column bars
            let columnBars = '';
            timeSeriesData.forEach((d, idx) => {
                const x = padding + idx * spacing;
                const barHeight = (d.time / maxTime) * plotHeight;
                const y = graphHeight - padding - barHeight;
                const color = d.method === 'RULE' ? '#ef4444' : '#3b82f6';
                
                columnBars += `<rect x="${x - barWidth/2}" y="${y}" width="${barWidth}" height="${barHeight}" fill="${color}" opacity="0.8"/>`;
            });
            
            // Overall average line
            const avgY = graphHeight - padding - (parseFloat(overallAvg) / maxTime) * plotHeight;
            
            const inferenceTimeStats = document.getElementById('inferenceTimeStats');
            inferenceTimeStats.innerHTML = `
                <div style="background: white; padding: 20px; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.06);">
                    <svg width="${graphWidth}" height="${graphHeight}" style="display: block; margin: 0 auto;">
                        <!-- Grid lines -->
                        <line x1="${padding}" y1="${padding}" x2="${padding}" y2="${graphHeight - padding}" stroke="#e5e7eb" stroke-width="2"/>
                        <line x1="${padding}" y1="${graphHeight - padding}" x2="${graphWidth - padding}" y2="${graphHeight - padding}" stroke="#e5e7eb" stroke-width="2"/>
                        
                        <!-- Horizontal grid lines -->
                        <line x1="${padding}" y1="${padding + plotHeight * 0.25}" x2="${graphWidth - padding}" y2="${padding + plotHeight * 0.25}" stroke="#f3f4f6" stroke-width="1"/>
                        <line x1="${padding}" y1="${padding + plotHeight * 0.5}" x2="${graphWidth - padding}" y2="${padding + plotHeight * 0.5}" stroke="#f3f4f6" stroke-width="1"/>
                        <line x1="${padding}" y1="${padding + plotHeight * 0.75}" x2="${graphWidth - padding}" y2="${padding + plotHeight * 0.75}" stroke="#f3f4f6" stroke-width="1"/>
                        
                        <!-- Y-axis labels -->
                        <text x="${padding - 10}" y="${padding + 5}" text-anchor="end" font-size="12" fill="#6b7280">${maxTime.toFixed(0)}ms</text>
                        <text x="${padding - 10}" y="${padding + plotHeight * 0.25 + 5}" text-anchor="end" font-size="12" fill="#6b7280">${(maxTime * 0.75).toFixed(0)}ms</text>
                        <text x="${padding - 10}" y="${padding + plotHeight * 0.5 + 5}" text-anchor="end" font-size="12" fill="#6b7280">${(maxTime * 0.5).toFixed(0)}ms</text>
                        <text x="${padding - 10}" y="${padding + plotHeight * 0.75 + 5}" text-anchor="end" font-size="12" fill="#6b7280">${(maxTime * 0.25).toFixed(0)}ms</text>
                        <text x="${padding - 10}" y="${graphHeight - padding + 5}" text-anchor="end" font-size="12" fill="#6b7280">0ms</text>
                        
                        <!-- Column bars (thin lines) -->
                        ${columnBars}
                        
                        <!-- Overall average line -->
                        ${allTimes.length > 0 ? `
                            <line x1="${padding}" y1="${avgY}" x2="${graphWidth - padding}" y2="${avgY}" 
                                  stroke="#10b981" stroke-width="3" stroke-dasharray="8,4" opacity="0.9"/>
                            <text x="${graphWidth - padding - 10}" y="${avgY - 8}" font-size="12" fill="#10b981" font-weight="700" text-anchor="end">
                                Overall Avg: ${overallAvg}ms
                            </text>
                        ` : ''}
                        
                        <!-- Axis labels -->
                        <text x="${graphWidth / 2}" y="${graphHeight - 5}" text-anchor="middle" font-size="14" fill="#374151" font-weight="600">
                            Request Sequence
                        </text>
                        <text x="${padding - 35}" y="${graphHeight / 2}" text-anchor="middle" font-size="14" fill="#374151" font-weight="600" transform="rotate(-90, ${padding - 35}, ${graphHeight / 2})">
                            End-to-End Time (ms)
                        </text>
                    </svg>
                    
                    <div style="display: flex; justify-content: center; gap: 30px; margin-top: 20px; align-items: center;">
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <div style="width: 4px; height: 20px; background: #ef4444; border-radius: 2px;"></div>
                            <span style="font-size: 14px; color: #374151; font-weight: 600;">🛡️ RULE-BASED</span>
                        </div>
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <div style="width: 4px; height: 20px; background: #3b82f6; border-radius: 2px;"></div>
                            <span style="font-size: 14px; color: #374151; font-weight: 600;">🤖 ML-BASED</span>
                        </div>
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <div style="width: 24px; height: 3px; background: #10b981; border-radius: 2px;"></div>
                            <span style="font-size: 14px; color: #10b981; font-weight: 700;">Overall Average: ${overallAvg}ms (${allTimes.length} samples)</span>
                        </div>
                    </div>
                </div>
            `;
            
            // Recent detections
            const recentDetections = document.getElementById('recentDetections');
            recentDetections.innerHTML = data.recent.slice(0, 10).map(entry => `
                <div class="result-item ${entry.is_malicious ? 'malicious' : 'benign'}">
                    <span class="badge ${entry.is_malicious ? 'attack' : 'safe'}">
                        ${entry.is_malicious ? '🚨' : '✅'}
                    </span>
                    <span class="badge ${entry.risk_level.toLowerCase()}">${entry.risk_level}</span>
                    <strong>${entry.method}</strong> ${entry.path}
                    <span style="float: right; color: #6c757d;">${entry.timestamp.split('T')[1].split('.')[0]}</span>
                </div>
            `).join('');
        }
        
        // Load initial data
        setTimeout(() => {
            if (document.getElementById('stats').classList.contains('active')) {
                loadStats();
            }
        }, 500);
        
        // Incremental Training Functions
        async function loadIncrementalStats() {
            try {
                const response = await fetch('/api/incremental/stats');
                const data = await response.json();
                
                if (data.error) {
                    document.getElementById('incrementalStats').innerHTML = `
                        <div class="stat-card" style="grid-column: 1/-1;">
                            <p style="color: #dc3545;">⚠️ Incremental training not enabled</p>
                        </div>
                    `;
                    return;
                }
                
                // Update trigger count input
                const currentCount = data.current_log_count || 0;
                const triggerCount = data.progress_to_trigger ? data.progress_to_trigger.split('/')[1] : '200';
                document.getElementById('triggerCount').value = triggerCount;
                
                // Stats cards
                const statsCards = document.getElementById('incrementalStats');
                statsCards.innerHTML = `
                    <div class="stat-card">
                        <h3>${currentCount}</h3>
                        <p>Current Benign Logs</p>
                    </div>
                    <div class="stat-card">
                        <h3>${triggerCount}</h3>
                        <p>Trigger Threshold</p>
                    </div>
                    <div class="stat-card">
                        <h3>${data.total_trainings || 0}</h3>
                        <p>Total Trainings</p>
                    </div>
                    <div class="stat-card">
                        <h3>${data.is_training ? '🔄 Yes' : '✅ No'}</h3>
                        <p>Training In Progress</p>
                    </div>
                `;
                
                // Training history
                const historyContainer = document.getElementById('trainingHistory');
                if (data.training_history && data.training_history.length > 0) {
                    historyContainer.innerHTML = data.training_history.slice().reverse().map(entry => `
                        <div class="result-item">
                            <div style="margin-bottom: 10px;">
                                <span class="badge safe">✅ Completed</span>
                                <strong>${entry.logs_trained} logs trained</strong>
                                <span style="color: #6c757d; float: right;">${new Date(entry.timestamp).toLocaleString()}</span>
                            </div>
                            <p><strong>Epochs:</strong> ${entry.epochs} | <strong>Time:</strong> ${(entry.training_time_seconds / 60).toFixed(2)} minutes</p>
                        </div>
                    `).join('');
                } else {
                    historyContainer.innerHTML = `
                        <div class="result-item">
                            <p style="color: #6c757d; text-align: center;">No training history yet</p>
                        </div>
                    `;
                }
            } catch (error) {
                console.error('Failed to load incremental stats:', error);
                document.getElementById('incrementalStats').innerHTML = `
                    <div class="stat-card" style="grid-column: 1/-1;">
                        <p style="color: #dc3545;">⚠️ Failed to load statistics</p>
                    </div>
                `;
            }
        }
        
        async function updateTriggerCount() {
            const triggerCount = document.getElementById('triggerCount').value;
            
            if (!triggerCount || triggerCount < 10) {
                alert('Trigger count must be at least 10');
                return;
            }
            
            try {
                const response = await fetch('/api/incremental/config', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({trigger_count: parseInt(triggerCount)})
                });
                
                const result = await response.json();
                
                if (result.error) {
                    alert('Error: ' + result.error);
                } else {
                    alert(`✅ Trigger threshold updated to ${result.trigger_count}`);
                    loadIncrementalStats();
                }
            } catch (error) {
                alert('Failed to update trigger count: ' + error);
            }
        }
        
        async function triggerTraining() {
            if (!confirm('Are you sure you want to manually trigger incremental training?')) {
                return;
            }
            
            try {
                const response = await fetch('/api/incremental/trigger', {method: 'POST'});
                const result = await response.json();
                
                if (result.status === 'training_started') {
                    alert('✅ Incremental training started! Check console logs for progress.');
                    setTimeout(loadIncrementalStats, 1000);
                } else {
                    alert('⚠️ Training already running or insufficient logs (need at least 10)');
                }
            } catch (error) {
                alert('Failed to trigger training: ' + error);
            }
        }
        
        async function clearLogs() {
            if (!confirm('Are you sure you want to clear all new benign logs? They will be backed up.')) {
                return;
            }
            
            try {
                const response = await fetch('/api/incremental/clear', {method: 'POST'});
                const result = await response.json();
                
                alert(`✅ Cleared ${result.count} logs (backup created)`);
                loadIncrementalStats();
            } catch (error) {
                alert('Failed to clear logs: ' + error);
            }
        }
        
        // ========================================================================
        // Admin Functions
        // ========================================================================
        
        let isAdminLoggedIn = false;
        
        async function adminLogin() {
            const username = document.getElementById('adminUsername').value;
            const password = document.getElementById('adminPassword').value;
            
            if (!username || !password) {
                alert('Please enter both username and password');
                return;
            }
            
            try {
                const response = await fetch('/api/admin/login', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({username, password})
                });
                
                const result = await response.json();
                
                if (result.success) {
                    isAdminLoggedIn = true;
                    document.getElementById('adminLogin').style.display = 'none';
                    document.getElementById('adminPanel').style.display = 'block';
                    loadSignatures();
                    loadAttackStats();
                } else {
                    alert('❌ Invalid credentials');
                }
            } catch (error) {
                alert('Login failed: ' + error);
            }
        }
        
        async function adminLogout() {
            try {
                await fetch('/api/admin/logout', {method: 'POST'});
                isAdminLoggedIn = false;
                document.getElementById('adminLogin').style.display = 'block';
                document.getElementById('adminPanel').style.display = 'none';
                document.getElementById('adminUsername').value = '';
                document.getElementById('adminPassword').value = '';
            } catch (error) {
                console.error('Logout failed:', error);
            }
        }
        
        async function loadSignatures() {
            try {
                const response = await fetch('/api/admin/signatures');
                const data = await response.json();
                
                if (data.error) {
                    alert('Error: ' + data.error);
                    return;
                }
                
                // Update stats
                document.getElementById('signatureStats').innerHTML = `
                    <div class="stat-card">
                        <h3>${data.total_attacks}</h3>
                        <p>Attack Logs</p>
                    </div>
                    <div class="stat-card">
                        <h3>${data.signature_categories}</h3>
                        <p>Signature Categories</p>
                    </div>
                    <div class="stat-card">
                        <h3>${data.total_patterns}</h3>
                        <p>Total Patterns</p>
                    </div>
                `;
                
                // Display signatures by category
                const signatureList = document.getElementById('signatureList');
                signatureList.innerHTML = '';
                
                if (data.total_patterns === 0) {
                    signatureList.innerHTML = `
                        <div class="result-item">
                            <p style="color: #6c757d; text-align: center;">No signatures extracted yet. ML-detected attacks will appear here.</p>
                        </div>
                    `;
                    return;
                }
                
                for (const [category, patterns] of Object.entries(data.signatures)) {
                    if (patterns.length === 0) continue;
                    
                    const categoryDiv = document.createElement('div');
                    categoryDiv.innerHTML = `<div class="category-header">${category.replace(/_/g, ' ').toUpperCase()} (${patterns.length})</div>`;
                    signatureList.appendChild(categoryDiv);
                    
                    patterns.forEach((pattern, idx) => {
                        const sigDiv = document.createElement('div');
                        sigDiv.className = 'signature-item';
                        sigDiv.innerHTML = `
                            <label style="cursor: pointer; display: flex; align-items: flex-start;">
                                <input type="checkbox" class="signature-checkbox" data-category="${category}" data-pattern="${pattern}">
                                <div style="flex: 1;">
                                    <strong>Pattern ${idx + 1}</strong>
                                    <div class="signature-pattern">${pattern}</div>
                                </div>
                            </label>
                        `;
                        signatureList.appendChild(sigDiv);
                    });
                }
                
            } catch (error) {
                alert('Failed to load signatures: ' + error);
            }
        }
        
        async function loadAttackStats() {
            try {
                const response = await fetch('/api/admin/attack-stats');
                const data = await response.json();
                
                const statsDiv = document.getElementById('attackStats');
                
                if (data.total_attacks === 0) {
                    statsDiv.innerHTML = `
                        <div class="result-item">
                            <p style="color: #6c757d; text-align: center;">No attack logs yet</p>
                        </div>
                    `;
                    return;
                }
                
                statsDiv.innerHTML = `
                    <div class="result-item">
                        <h4>By Threat Type</h4>
                        ${Object.entries(data.by_threat_type).map(([type, count]) => `
                            <p><strong>${type}:</strong> ${count}</p>
                        `).join('')}
                    </div>
                    <div class="result-item">
                        <h4>By Risk Level</h4>
                        ${Object.entries(data.by_risk_level).map(([level, count]) => `
                            <p><span class="badge ${level.toLowerCase()}">${level}</span> ${count}</p>
                        `).join('')}
                    </div>
                `;
            } catch (error) {
                console.error('Failed to load attack stats:', error);
            }
        }
        
        async function approveSelected() {
            const checkboxes = document.querySelectorAll('.signature-checkbox:checked');
            
            if (checkboxes.length === 0) {
                alert('Please select at least one signature to approve');
                return;
            }
            
            if (!confirm(`Are you sure you want to add ${checkboxes.length} signature(s) to Redis?`)) {
                return;
            }
            
            // Organize selected patterns by category
            const selectedSignatures = {};
            checkboxes.forEach(cb => {
                const category = cb.dataset.category;
                const pattern = cb.dataset.pattern;
                if (!selectedSignatures[category]) {
                    selectedSignatures[category] = [];
                }
                selectedSignatures[category].push(pattern);
            });
            
            try {
                const response = await fetch('/api/admin/approve-signatures', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({signatures: selectedSignatures})
                });
                
                const result = await response.json();
                
                if (result.success) {
                    const message = `✅ Successfully added ${result.patterns_added} pattern(s) to Redis!\n\n` +
                                  `📊 Categories updated: ${result.categories_updated}\n` +
                                  `💾 Backup created: ${result.backup_created ? 'Yes' : 'No'}\n` +
                                  `🗑️  Attack logs cleared: ${result.logs_cleared}\n\n` +
                                  `The signatures are now active and protecting your application!`;
                    alert(message);
                    loadSignatures();
                    loadAttackStats();
                } else {
                    alert('Error: ' + result.error);
                }
            } catch (error) {
                alert('Failed to approve signatures: ' + error);
            }
        }
        
        async function clearAttackLogs() {
            if (!confirm('Are you sure you want to clear all attack logs? They will be backed up.')) {
                return;
            }
            
            try {
                const response = await fetch('/api/admin/clear-attacks', {method: 'POST'});
                const result = await response.json();
                
                alert(`✅ Cleared ${result.count} attack logs (backup created)`);
                loadSignatures();
                loadAttackStats();
            } catch (error) {
                alert('Failed to clear attack logs: ' + error);
            }
        }
        
        // Update showTab to check admin authentication
        const originalShowTab = showTab;
        showTab = function(tabName) {
            if (tabName === 'admin' && !isAdminLoggedIn) {
                // Show login screen
                document.getElementById('adminLogin').style.display = 'block';
                document.getElementById('adminPanel').style.display = 'none';
            } else if (tabName === 'admin' && isAdminLoggedIn) {
                // Show admin panel
                document.getElementById('adminLogin').style.display = 'none';
                document.getElementById('adminPanel').style.display = 'block';
                loadSignatures();
                loadAttackStats();
            }
            
            // Call original function
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            
            event.target.classList.add('active');
            document.getElementById(tabName).classList.add('active');
            
            if (tabName === 'monitoring') {
                startAutoRefresh();
            } else if (tabName === 'stats') {
                loadStats();
                stopAutoRefresh();
            } else if (tabName === 'incremental') {
                loadIncrementalStats();
                stopAutoRefresh();
            } else {
                stopAutoRefresh();
            }
        };
    </script>
</body>
</html>
"""

# ============================================================================
# FLASK ROUTES
# ============================================================================

@app.route('/isro_logo.jpg')
def serve_logo():
    """Serve the ISRO logo"""
    from flask import send_file
    return send_file('isro_logo.jpg', mimetype='image/jpeg')

@app.route('/')
def index():
    """Main UI"""
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/test-curl', methods=['POST'])
def api_test_curl():
    """Test a curl command"""
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        curl_cmd = data.get('curl_command', '')
        
        if not curl_cmd:
            return jsonify({'error': 'No curl command provided'}), 400
        
        result = execute_curl_test(curl_cmd)
        return jsonify(result)
    except Exception as e:
        print(f"❌ Error in api_test_curl: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Server error: {str(e)}'}), 500

@app.route('/api/monitoring/start', methods=['POST'])
def api_start_monitoring():
    """Start log monitoring"""
    start_monitoring()
    return jsonify({'status': 'started'})

@app.route('/api/monitoring/stop', methods=['POST'])
def api_stop_monitoring():
    """Stop log monitoring"""
    stop_monitoring()
    return jsonify({'status': 'stopped'})

@app.route('/api/monitoring/results')
def api_monitoring_results():
    """Get monitoring results"""
    results = list(log_monitor_results)
    results.reverse()
    return jsonify({'results': results})

@app.route('/api/stats')
def api_stats():
    """Get statistics"""
    all_results = list(log_monitor_results) + list(test_results)
    
    total = len(all_results)
    attacks = sum(1 for r in all_results if r.get('is_malicious') or r.get('waf_result', {}).get('is_malicious'))
    benign = total - attacks
    
    by_method = {}
    for r in all_results:
        method = r.get('detection_method') or r.get('waf_result', {}).get('detection_method', 'UNKNOWN')
        by_method[method] = by_method.get(method, 0) + 1
    
    recent = []
    for r in list(log_monitor_results)[-20:]:
        recent.append(r)
    for r in list(test_results)[-20:]:
        if 'waf_result' in r:
            recent.append({
                'timestamp': r['timestamp'],
                'method': r['request']['method'],
                'path': r['request']['path'],
                'is_malicious': r['waf_result']['is_malicious'],
                'risk_level': r['waf_result']['risk_level'],
                'detection_method': r['waf_result'].get('detection_method', 'UNKNOWN'),
                'inference_time_ms': r['waf_result'].get('inference_time_ms', 0.0),
                'total_time_ms': r.get('total_time_ms', 0.0),
            })
    
    recent.sort(key=lambda x: x['timestamp'], reverse=True)
    
    stats_dict = {
        'total_requests': total,
        'attacks_detected': attacks,
        'benign_requests': benign,
        'detection_rate': (attacks / total * 100) if total > 0 else 0,
        'by_method': by_method,
        'recent': recent[:20]
    }
    
    # Add incremental training stats if available
    if incremental_manager:
        inc_stats = incremental_manager.get_stats()
        stats_dict['incremental'] = inc_stats
    
    return jsonify(stats_dict)

@app.route('/api/incremental/stats')
def api_incremental_stats():
    """Get incremental training statistics"""
    if not incremental_manager:
        return jsonify({'error': 'Incremental manager not initialized'}), 400
    
    stats = incremental_manager.get_stats()
    return jsonify(stats)

@app.route('/api/incremental/trigger', methods=['POST'])
def api_incremental_trigger():
    """Manually trigger incremental training"""
    if not incremental_manager:
        return jsonify({'error': 'Incremental manager not initialized'}), 400
    
    success = incremental_manager.trigger_training_manually()
    if success:
        return jsonify({'status': 'training_started'})
    else:
        return jsonify({'status': 'training_already_running_or_insufficient_logs'}), 400

@app.route('/api/incremental/config', methods=['POST'])
def api_incremental_config():
    """Update incremental training configuration"""
    if not incremental_manager:
        return jsonify({'error': 'Incremental manager not initialized'}), 400
    
    data = request.json
    trigger_count = data.get('trigger_count')
    
    if trigger_count:
        success = incremental_manager.update_trigger_count(int(trigger_count))
        if success:
            return jsonify({'status': 'updated', 'trigger_count': incremental_manager.trigger_count})
        else:
            return jsonify({'error': 'Invalid trigger count (min: 10)'}), 400
    
    return jsonify({'error': 'No valid parameters provided'}), 400

@app.route('/api/incremental/clear', methods=['POST'])
def api_incremental_clear():
    """Clear new benign logs"""
    if not incremental_manager:
        return jsonify({'error': 'Incremental manager not initialized'}), 400
    
    count = incremental_manager.clear_logs()
    return jsonify({'status': 'cleared', 'count': count})

# ============================================================================
# ADMIN API ROUTES
# ============================================================================

@app.route('/api/admin/login', methods=['POST'])
def api_admin_login():
    """Admin login"""
    data = request.json
    username = data.get('username', '')
    password = data.get('password', '')
    
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        session['admin_authenticated'] = True
        admin_sessions.add(session.sid if hasattr(session, 'sid') else id(session))
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

@app.route('/api/admin/logout', methods=['POST'])
def api_admin_logout():
    """Admin logout"""
    session.pop('admin_authenticated', None)
    return jsonify({'success': True})

def require_admin():
    """Check if user is authenticated as admin"""
    return session.get('admin_authenticated', False)

@app.route('/api/admin/signatures')
def api_admin_signatures():
    """Get pending signatures"""
    if not require_admin():
        return jsonify({'error': 'Unauthorized'}), 401
    
    if not signature_manager:
        return jsonify({'error': 'Signature manager not initialized'}), 400
    
    pending = signature_manager.get_pending_signatures()
    return jsonify(pending)

@app.route('/api/admin/attack-stats')
def api_admin_attack_stats():
    """Get attack log statistics"""
    if not require_admin():
        return jsonify({'error': 'Unauthorized'}), 401
    
    if not signature_manager:
        return jsonify({'error': 'Signature manager not initialized'}), 400
    
    stats = signature_manager.get_stats()
    return jsonify(stats)

@app.route('/api/admin/reload-rules', methods=['POST'])
def api_admin_reload_rules():
    """Reload rules from Redis without restarting the server"""
    global compiled_rules
    
    try:
        old_count = sum(len(patterns) for patterns in compiled_rules.values())
        
        # Reconnect to Redis and reload all rules
        print("🔄 Reloading rules from Redis...")
        initialize_redis_rules()
        
        new_count = sum(len(patterns) for patterns in compiled_rules.values())
        added = new_count - old_count
        
        print(f"✅ Rules reloaded: {old_count} → {new_count} (+{added})")
        
        return jsonify({
            'success': True,
            'old_count': old_count,
            'new_count': new_count,
            'added': added,
            'categories': {cat: len(patterns) for cat, patterns in compiled_rules.items()}
        })
    except Exception as e:
        print(f"❌ Failed to reload rules: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/admin/approve-signatures', methods=['POST'])
def api_admin_approve_signatures():
    """Approve selected signatures and add to Redis"""
    if not require_admin():
        return jsonify({'error': 'Unauthorized'}), 401
    
    if not signature_manager:
        return jsonify({'error': 'Signature manager not initialized'}), 400
    
    data = request.json
    selected_signatures = data.get('signatures', {})
    
    if not selected_signatures:
        return jsonify({'error': 'No signatures provided'}), 400
    
    try:
        # Add signatures to Redis
        categories_updated = 0
        patterns_added = 0
        
        for category, patterns in selected_signatures.items():
            if not patterns:
                continue
            
            # Add to Redis if available
            if redis_manager:
                for pattern in patterns:
                    success = redis_manager.add_rule(category, pattern)
                    if success:
                        patterns_added += 1
                        print(f"✅ Added to Redis [{category}]: {pattern}")
                    else:
                        print(f"⚠️  Failed to add to Redis [{category}]: {pattern}")
                categories_updated += 1
            
            # Also add to compiled_rules for immediate use
            if category not in compiled_rules:
                compiled_rules[category] = []
            
            for pattern in patterns:
                try:
                    compiled_pattern = re.compile(pattern, re.IGNORECASE)
                    compiled_rules[category].append(compiled_pattern)
                except re.error as e:
                    print(f"⚠️  Failed to compile pattern: {pattern[:50]}... - {e}")
        
        # Backup the updated rules to rules_backup.json (just like init_redis_rules.py)
        backup_success = False
        if redis_manager and patterns_added > 0:
            backup_file = "rules_backup.json"
            backup_success = redis_manager.export_rules_to_json(backup_file)
            if backup_success:
                print(f"💾 Backed up {patterns_added} new pattern(s) to {backup_file}")
            else:
                print(f"⚠️  Failed to backup rules to {backup_file}")
        
        # Clear attack logs after successful approval so approved signatures don't show up again
        logs_cleared = 0
        if patterns_added > 0:
            logs_cleared = signature_manager.clear_attack_logs(backup=True)
            print(f"🗑️  Cleared {logs_cleared} attack log(s) after approval (backup created)")
        
        return jsonify({
            'success': True,
            'categories_updated': categories_updated,
            'patterns_added': patterns_added,
            'backup_created': backup_success,
            'logs_cleared': logs_cleared
        })
        
    except Exception as e:
        print(f"❌ Error approving signatures: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/clear-attacks', methods=['POST'])
def api_admin_clear_attacks():
    """Clear attack logs"""
    if not require_admin():
        return jsonify({'error': 'Unauthorized'}), 401
    
    if not signature_manager:
        return jsonify({'error': 'Signature manager not initialized'}), 400
    
    count = signature_manager.clear_attack_logs(backup=True)
    return jsonify({'status': 'cleared', 'count': count})

@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def catch_all(path):
    """Catch-all route to analyze ANY request sent to the WAF"""
    print(f"\n{'='*60}\n🔍 CATCH-ALL ROUTE TRIGGERED: /{path}\n{'='*60}")
    
    request_dict = {
        'method': request.method,
        'path': '/' + path,
        'query': dict(request.args),
        'headers': dict(request.headers),
        'body': request.get_data(as_text=True) if request.data else None,
    }
    
    # Run hierarchical detection
    result = hierarchical_detect(request_dict)
    
    # Log result with emoji indicator
    status_icon = "🔴 BLOCKED" if result.is_malicious else "✅ SAFE"
    print(f"{status_icon} {result.risk_level} {result.detection_method} {datetime.now().isoformat()}")
    print(f"Request: {request.method} /{path}")
    if result.is_malicious:
        print(f"Threat Type: {result.threat_type}")
        print(f"Confidence: {result.confidence}%")
        print(f"Matched Patterns: {len(result.matched_patterns) if hasattr(result, 'matched_patterns') else 0}")
    else:
        print(f"Threat Type: {result.threat_type}")
        print(f"Confidence: {result.confidence}%")
        print(f"Anomaly Score: {result.anomaly_score:.4f}")
    print()
    
    # Return WAF response
    if result.is_malicious:
        return jsonify({
            'blocked': True,
            'reason': result.threat_type,
            'confidence': result.confidence,
            'risk_level': result.risk_level,
            'detection_method': result.detection_method,
        }), 403
    else:
        return jsonify({
            'allowed': True,
            'confidence': result.confidence,
            'anomaly_score': result.anomaly_score,
        }), 200

# ============================================================================
# INITIALIZATION
# ============================================================================

def initialize_waf(
    model_path: str = "models/deberta-waf/best_model",
    calibration_file: str = "data/parsed/parsed_requests.json",
    incremental_trigger_count: int = 200,
    incremental_epochs: int = 2,
    enable_incremental: bool = True
):
    """Initialize WAF detector with Redis-based rules and incremental training"""
    global detector, incremental_manager, signature_manager
    
    print("=" * 80)
    print("🛡️  Initializing Integrated WAF System with Redis Rules")
    print("=" * 80)
    
    # Initialize Redis rules first (400+ patterns)
    print("\n🎯 Initializing comprehensive rule-based detection...")
    redis_connected = initialize_redis_rules()
    
    total_patterns = sum(len(patterns) for patterns in compiled_rules.values())
    print(f"\n✅ Total patterns loaded: {total_patterns}")
    
    print("\n📦 Loading ML model...")
    detector = WAFDetector(
        model_path=model_path,
        threshold_percentile=98.0  # Increased from 95.0 to reduce false positives
    )
    
    print(f"\n📊 Loading calibration data from {calibration_file}...")
    try:
        with open(calibration_file, 'r') as f:
            benign_data = json.load(f)
        # Use ALL samples for accurate threshold estimation (was 100, now using all ~2729)
        detector.calibrate(benign_data, num_samples=100)
        print("✅ Calibration complete")
    except Exception as e:
        print(f"⚠️  Calibration failed: {e}")
    
    # Initialize signature manager
    print("\n📝 Initializing signature manager...")
    try:
        signature_manager = get_signature_manager()
        attack_count = signature_manager.get_attack_count()
        print(f"✅ Signature manager enabled")
        print(f"   - Current attack logs: {attack_count}")
    except Exception as e:
        print(f"⚠️  Signature manager initialization failed: {e}")
        signature_manager = None
    
    # Initialize incremental training manager
    if enable_incremental:
        print("\n🔄 Initializing incremental training manager...")
        try:
            incremental_manager = get_incremental_manager(
                trigger_count=incremental_trigger_count,
                training_epochs=incremental_epochs,
                auto_train=True
            )
            current_logs = incremental_manager.get_log_count()
            print(f"✅ Incremental training enabled")
            print(f"   - Trigger threshold: {incremental_trigger_count} logs")
            print(f"   - Training epochs: {incremental_epochs}")
            print(f"   - Current benign logs: {current_logs}")
        except Exception as e:
            print(f"⚠️  Incremental training initialization failed: {e}")
            incremental_manager = None
    else:
        print("\n⚠️  Incremental training disabled")
    
    print("\n✅ Integrated WAF System Ready!")
    print(f"   - Redis: {'Connected' if redis_connected else 'Fallback to Static'}")
    print(f"   - Rule Patterns: {total_patterns}")
    print(f"   - ML Model: Loaded")
    print(f"   - Signature Manager: {'Enabled' if signature_manager else 'Disabled'}")
    print(f"   - Incremental Training: {'Enabled' if incremental_manager else 'Disabled'}")
    print("=" * 80)

# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Integrated WAF Testing & Monitoring UI')
    parser.add_argument('--port', type=int, default=5000, help='Port for web UI')
    parser.add_argument('--model-path', type=str, default='models/deberta-waf/best_model')
    parser.add_argument('--calibration-file', type=str, default='data/parsed/parsed_requests.json')
    parser.add_argument('--incremental-trigger', type=int, default=200, help='Number of logs to trigger incremental training')
    parser.add_argument('--incremental-epochs', type=int, default=2, help='Number of epochs for incremental training')
    parser.add_argument('--disable-incremental', action='store_true', help='Disable incremental training')
    args = parser.parse_args()
    
    initialize_waf(
        model_path=args.model_path,
        calibration_file=args.calibration_file,
        incremental_trigger_count=args.incremental_trigger,
        incremental_epochs=args.incremental_epochs,
        enable_incremental=not args.disable_incremental
    )
    
    print(f"\n🚀 Starting Integrated WAF UI on http://localhost:{args.port}")
    print("\nPress Ctrl+C to stop\n")
    
    app.run(host='0.0.0.0', port=args.port, debug=False, threaded=True)
