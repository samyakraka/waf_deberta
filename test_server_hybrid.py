"""
Enhanced WAF Server with Hybrid Detection
Combines ML-based anomaly detection with rule-based pattern matching
Author: ISRO WAF Team
"""

import os
os.environ['TOKENIZERS_PARALLELISM'] = 'false'

import json
import sys
from pathlib import Path
from datetime import datetime
from flask import Flask, request, jsonify, Response
import logging
import re

# Add src to path
sys.path.append(str(Path(__file__).parent))

from src.detector import WAFDetector

# Initialize Flask app
app = Flask(__name__)

# Suppress Flask logs (optional)
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# Global detector instance
detector = None
detection_log = []

# ============================================================================
# RULE-BASED DETECTION PATTERNS
# ============================================================================

# Suspicious path patterns
SUSPICIOUS_PATHS = [
    r'/etc/passwd', r'/etc/shadow', r'/etc/hosts',
    r'\.\./.*', r'\.\.\\.*',  # Directory traversal
    r'/proc/', r'/sys/',
    r'cmd\.exe', r'/bin/bash', r'/bin/sh',
    r'/admin', r'/administrator',
    r'\.\.', r'%2e%2e',  # Encoded dots
]

# SQL injection patterns
SQL_PATTERNS = [
    r"(\bor\b|\band\b)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",  # OR 1=1
    r"'\s*or\s*'.*'\s*=\s*'",  # ' OR '1'='1
    r"\"\s*or\s*\".*\"\s*=\s*\"",  # " OR "1"="1
    r"'\s*or\s*1\s*=\s*1",  # ' OR 1=1
    r"\"\s*or\s*1\s*=\s*1",  # " OR 1=1
    r"'\s*or\s*'[^']*'\s*[=><!]",  # ' OR 'x'>
    r"union\s+select",
    r";\s*drop\s+table",
    r";\s*delete\s+from",
    r"'\s+or\s+'",
    r"--\s*$",  # SQL comments
    r"#.*$",  # MySQL comments
    r"\/\*.*\*\/",  # SQL block comments
    r"';\s*--",  # SQL injection with comment
    r"'\s*;\s*--",
]

# XSS patterns
XSS_PATTERNS = [
    r'<script[^>]*>',
    r'javascript:',
    r'onerror\s*=',
    r'onload\s*=',
    r'<iframe',
    r'<embed',
    r'alert\s*\(',
    r'eval\s*\(',
]

# Command injection patterns
CMD_PATTERNS = [
    r';\s*(ls|cat|wget|curl|nc|netcat|bash|sh)',
    r'\|\s*(ls|cat|wget|curl|nc|netcat|bash|sh)',
    r'&&\s*(ls|cat|wget|curl|nc|netcat|bash|sh)',
    r'`.*`',  # Backtick command substitution
    r'\$\(.*\)',  # Command substitution
]

# Encoding evasion patterns
ENCODING_PATTERNS = [
    r'%00',  # Null byte
    r'%0d%0a',  # CRLF
    r'%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}',  # Triple encoded
]


def check_rule_based_threats(request_dict: dict) -> tuple[bool, str, list]:
    """
    Check for known attack patterns using regex rules
    
    Returns:
        (is_threat, threat_type, matched_patterns)
    """
    path = request_dict.get('path', '').lower()
    query = str(request_dict.get('query', {})).lower()
    body = str(request_dict.get('body', '')).lower()
    
    full_text = f"{path} {query} {body}"
    
    matched_patterns = []
    
    # Check path traversal
    for pattern in SUSPICIOUS_PATHS:
        if re.search(pattern, full_text, re.IGNORECASE):
            matched_patterns.append(('Path Traversal/LFI', pattern))
    
    # Check SQL injection
    for pattern in SQL_PATTERNS:
        if re.search(pattern, full_text, re.IGNORECASE):
            matched_patterns.append(('SQL Injection', pattern))
    
    # Check XSS
    for pattern in XSS_PATTERNS:
        if re.search(pattern, full_text, re.IGNORECASE):
            matched_patterns.append(('XSS', pattern))
    
    # Check command injection
    for pattern in CMD_PATTERNS:
        if re.search(pattern, full_text, re.IGNORECASE):
            matched_patterns.append(('Command Injection', pattern))
    
    # Check encoding evasion
    for pattern in ENCODING_PATTERNS:
        if re.search(pattern, full_text, re.IGNORECASE):
            matched_patterns.append(('Encoding Evasion', pattern))
    
    if matched_patterns:
        threat_types = list(set([m[0] for m in matched_patterns]))
        return True, ', '.join(threat_types), matched_patterns
    
    return False, '', []


def hybrid_detect(request_dict: dict):
    """
    Hybrid detection combining ML and rule-based approaches
    
    Returns:
        Enhanced detection result with both ML and rule-based info
    """
    # ML-based detection
    ml_result = detector.detect(request_dict)
    
    # Rule-based detection
    rule_triggered, threat_type, matched_patterns = check_rule_based_threats(request_dict)
    
    # Combine results
    if rule_triggered and not ml_result.is_malicious:
        # Rule caught it but ML didn't
        is_malicious = True
        confidence = 90.0
        risk_level = "HIGH"
        detection_method = "RULE"
    elif ml_result.is_malicious and rule_triggered:
        # Both caught it - high confidence
        is_malicious = True
        confidence = min(99.9, ml_result.confidence + 20.0)
        risk_level = "CRITICAL"
        detection_method = "HYBRID"
    elif ml_result.is_malicious:
        # Only ML caught it
        is_malicious = True
        confidence = ml_result.confidence
        risk_level = ml_result.risk_level
        detection_method = "ML"
    else:
        # Neither caught it
        is_malicious = False
        confidence = ml_result.confidence
        risk_level = ml_result.risk_level
        detection_method = "CLEAN"
    
    # Create enhanced result
    class HybridResult:
        def __init__(self):
            self.is_malicious = is_malicious
            self.confidence = confidence
            self.reconstruction_loss = ml_result.reconstruction_loss
            self.anomaly_score = ml_result.anomaly_score
            self.risk_level = risk_level
            self.detection_method = detection_method
            # Fix threat_type label for clean requests
            if rule_triggered:
                self.threat_type = threat_type
            elif is_malicious:
                self.threat_type = 'Unknown Anomaly'
            else:
                self.threat_type = 'None'
            self.matched_patterns = matched_patterns
            self.ml_details = ml_result.details
    
    return HybridResult()


def initialize_detector(
    model_path: str = "models/deberta-waf/best_model",
    calibration_file: str = "data/parsed/parsed_requests.json",
    threshold_percentile: float = 85.0  # Balanced threshold
):
    """Initialize and calibrate the WAF detector"""
    global detector
    
    print("=" * 80)
    print("🛡️  Initializing Enhanced Hybrid WAF Server")
    print("=" * 80)
    
    print("\n📦 Loading ML model...")
    detector = WAFDetector(
        model_path=model_path,
        threshold_percentile=threshold_percentile
    )
    
    print(f"\n📊 Loading calibration data from {calibration_file}...")
    with open(calibration_file, 'r') as f:
        benign_data = json.load(f)
    
    detector.calibrate(benign_data, num_samples=100)
    
    print("\n🎯 Rule-based detection enabled:")
    print(f"   - Path Traversal/LFI: {len(SUSPICIOUS_PATHS)} patterns")
    print(f"   - SQL Injection: {len(SQL_PATTERNS)} patterns")
    print(f"   - XSS: {len(XSS_PATTERNS)} patterns")
    print(f"   - Command Injection: {len(CMD_PATTERNS)} patterns")
    print(f"   - Encoding Evasion: {len(ENCODING_PATTERNS)} patterns")
    
    print("\n✅ Enhanced Hybrid WAF Ready!")
    print("=" * 80)


def parse_flask_request(req) -> dict:
    """Convert Flask request to detector format"""
    from urllib.parse import unquote
    
    request_dict = {
        'method': req.method,
        'path': req.path,
        'headers': dict(req.headers),
        'query': dict(req.args),
        'body': ''
    }
    
    # Get body if present
    if req.data:
        try:
            body_str = req.data.decode('utf-8')
            # Decode URL-encoded data
            request_dict['body'] = unquote(body_str)
        except:
            request_dict['body'] = str(req.data)
    
    # Try to parse JSON body
    if req.is_json:
        try:
            request_dict['body'] = json.dumps(req.get_json())
        except:
            pass
    
    # Also check form data
    if req.form:
        form_data = ' '.join([f"{k}={v}" for k, v in req.form.items()])
        request_dict['body'] += ' ' + form_data
    
    return request_dict


def log_detection(request_dict: dict, result, client_ip: str):
    """Log detection result"""
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'client_ip': client_ip,
        'method': request_dict['method'],
        'path': request_dict['path'],
        'is_malicious': result.is_malicious,
        'risk_level': result.risk_level,
        'confidence': result.confidence,
        'reconstruction_loss': result.reconstruction_loss,
        'anomaly_score': result.anomaly_score,
        'detection_method': getattr(result, 'detection_method', 'ML'),
        'threat_type': getattr(result, 'threat_type', 'N/A')
    }
    detection_log.append(log_entry)
    
    # Keep only last 1000 entries
    if len(detection_log) > 1000:
        detection_log.pop(0)
    
    return log_entry


@app.before_request
def check_request():
    """Check every request for malicious content"""
    if detector is None:
        return jsonify({'error': 'WAF not initialized'}), 500
    
    # Skip health check and monitoring endpoints
    if request.path in ['/health', '/waf/stats', '/waf/logs']:
        return None
    
    # Parse request
    request_dict = parse_flask_request(request)
    
    # Hybrid detection
    result = hybrid_detect(request_dict)
    
    # Log detection
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    log_entry = log_detection(request_dict, result, client_ip)
    
    # Print to console with more details
    if result.is_malicious:
        status_emoji = "🚨"
        color = "\033[91m"  # Red
    else:
        status_emoji = "✅"
        color = "\033[92m"  # Green
    
    reset = "\033[0m"
    
    print(f"\n{color}{status_emoji} [{datetime.now().strftime('%H:%M:%S')}] "
          f"{request.method} {request.path}{reset}")
    print(f"   Risk: {result.risk_level} | "
          f"Method: {result.detection_method} | "
          f"Loss: {result.reconstruction_loss:.4f} | "
          f"Confidence: {result.confidence:.1f}%")
    
    if result.is_malicious and hasattr(result, 'threat_type'):
        print(f"   Threat: {result.threat_type}")
    
    # Block if malicious (configurable)
    if result.is_malicious and result.risk_level in ['HIGH', 'CRITICAL']:
        response = {
            'blocked': True,
            'reason': f'Malicious request detected: {result.threat_type}',
            'risk_level': result.risk_level,
            'confidence': result.confidence,
            'detection_method': result.detection_method,
            'anomaly_score': result.anomaly_score,
            'timestamp': datetime.now().isoformat()
        }
        return jsonify(response), 403
    
    # Allow request with detailed info
    response = {
        'blocked': False,
        'message': 'Request allowed',
        'risk_level': result.risk_level,
        'confidence': result.confidence,
        'detection_method': result.detection_method,
        'anomaly_score': result.anomaly_score,
        'threat_type': result.threat_type if hasattr(result, 'threat_type') else 'None',
        'timestamp': datetime.now().isoformat()
    }
    return jsonify(response), 200


# ============================================================================
# MONITORING ENDPOINTS
# ============================================================================

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'detector_ready': detector is not None,
        'timestamp': datetime.now().isoformat()
    })


@app.route('/waf/stats')
def waf_stats():
    """Get WAF statistics"""
    if not detection_log:
        return jsonify({'message': 'No requests logged yet'})
    
    total = len(detection_log)
    malicious = sum(1 for log in detection_log if log['is_malicious'])
    benign = total - malicious
    
    # Count by risk level
    risk_counts = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
    for log in detection_log:
        risk_counts[log['risk_level']] += 1
    
    # Count by detection method
    method_counts = {}
    for log in detection_log:
        method = log.get('detection_method', 'ML')
        method_counts[method] = method_counts.get(method, 0) + 1
    
    # Count by threat type
    threat_counts = {}
    for log in detection_log:
        if log['is_malicious']:
            threat = log.get('threat_type', 'Unknown')
            threat_counts[threat] = threat_counts.get(threat, 0) + 1
    
    return jsonify({
        'total_requests': total,
        'malicious_requests': malicious,
        'benign_requests': benign,
        'malicious_percentage': round(malicious / total * 100, 2),
        'risk_distribution': risk_counts,
        'detection_methods': method_counts,
        'threat_types': threat_counts,
        'timestamp': datetime.now().isoformat()
    })


@app.route('/waf/logs')
def waf_logs():
    """Get recent detection logs"""
    count = request.args.get('count', 10, type=int)
    count = min(count, 1000)  # Max 1000
    
    recent_logs = detection_log[-count:]
    
    return jsonify({
        'count': len(recent_logs),
        'logs': recent_logs
    })


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    """Catch-all route for testing any path"""
    # This gets hit after check_request() processes it
    # If we're here, the request was allowed
    return jsonify({
        'message': 'Request processed by WAF',
        'path': request.path,
        'method': request.method,
        'status': 'allowed'
    })


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Enhanced Hybrid WAF Server')
    parser.add_argument('--port', type=int, default=8080,
                       help='Port to run server on')
    parser.add_argument('--model-path', type=str,
                       default='models/deberta-waf/best_model',
                       help='Path to trained model')
    parser.add_argument('--calibration-file', type=str,
                       default='data/parsed/parsed_requests.json',
                       help='Path to calibration data')
    parser.add_argument('--threshold', type=float, default=85.0,
                       help='Detection threshold percentile (lower=more sensitive)')
    parser.add_argument('--no-block', action='store_true',
                       help='Disable request blocking (log only)')
    
    args = parser.parse_args()
    
    # Initialize detector
    initialize_detector(
        model_path=args.model_path,
        calibration_file=args.calibration_file,
        threshold_percentile=args.threshold
    )
    
    # Run server
    print(f"\n🚀 Starting server on http://localhost:{args.port}")
    print(f"   Blocking mode: {'DISABLED (log only)' if args.no_block else 'ENABLED'}")
    print("\nPress Ctrl+C to stop\n")
    
    app.run(host='0.0.0.0', port=args.port, debug=False)
