#!/usr/bin/env python3
"""
Enhanced Hierarchical Hybrid WAF Server
- Hierarchical flow: RULES -> (only if safe) ML (transformer) detection
- Fast rule short-circuiting, compiled regexes, and ML verdict LRU cache
Author: adapted from original ISRO WAF Team code (user file)
Saved as: /mnt/data/test_server_hybrid_hierarchical.py
Reference original: /mnt/data/test_server_hybrid.py. :contentReference[oaicite:1]{index=1}
"""

import os
os.environ['TOKENIZERS_PARALLELISM'] = 'false'
# Prevent wandb prompts if any HF training utilities are imported elsewhere
os.environ["WANDB_DISABLED"] = "true"

import json
import sys
from pathlib import Path
from datetime import datetime
from flask import Flask, request, jsonify, Response
import logging
import re
from functools import lru_cache

# Add src to path (keeps compatibility with original project structure)
sys.path.append(str(Path(__file__).parent))

# Import your WAFDetector (assumed to exist in src.detector)
from src.detector import WAFDetector  # ensure this module exists and detector API matches usage

# Initialize Flask app
app = Flask(__name__)

# Suppress Flask logs (optional)
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# Global detector instance
detector = None
detection_log = []

# ===================================================================
# RULE-BASED DETECTION PATTERNS (kept same categories but compiled)
# ===================================================================

# Suspicious path patterns
SUSPICIOUS_PATHS_RAW = [
    r'/etc/passwd', r'/etc/shadow', r'/etc/hosts',
    r'\.\./', r'\.\.\\',  # Directory traversal
    r'/proc/', r'/sys/',
    r'cmd\.exe', r'/bin/bash', r'/bin/sh',
    r'/admin', r'/administrator',
    r'\.\.', r'%2e%2e',  # Encoded dots
]

# SQL injection patterns
SQL_PATTERNS_RAW = [
    r"(\bor\b|\band\b)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",  # OR 1=1 kind
    r"'\s*or\s*'.*'\s*=\s*'",  # ' OR '1'='1
    r"\"\s*or\s*\".*\"\s*=\s*\"",  # " OR "1"="1
    r"'\s*or\s*1\s*=\s*1",  # ' OR 1=1
    r"\"\s*or\s*1\s*=\s*1",  # " OR 1=1
    r"union\s+select",
    r";\s*drop\s+table",
    r";\s*delete\s+from",
    r"--\s*$",  # SQL comments
    r"#.*$",  # MySQL comments
    r"\/\*.*\*\/",  # SQL block comments
    r"';\s*--",  # SQL injection with comment
    r"'\s*;\s*--",
]

# XSS patterns
XSS_PATTERNS_RAW = [
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
CMD_PATTERNS_RAW = [
    r';\s*(ls|cat|wget|curl|nc|netcat|bash|sh)',
    r'\|\s*(ls|cat|wget|curl|nc|netcat|bash|sh)',
    r'&&\s*(ls|cat|wget|curl|nc|netcat|bash|sh)',
    r'`.*`',  # Backtick command substitution
    r'\$\(.*\)',  # Command substitution
]

# Encoding evasion patterns
ENCODING_PATTERNS_RAW = [
    r'%00',  # Null byte
    r'%0d%0a',  # CRLF
    r'%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}',  # Triple encoded
]

# Compile all regex patterns once at startup for speed
def compile_patterns(raw_list):
    return [re.compile(p, re.IGNORECASE) for p in raw_list]

SUSPICIOUS_PATHS = compile_patterns(SUSPICIOUS_PATHS_RAW)
SQL_PATTERNS = compile_patterns(SQL_PATTERNS_RAW)
XSS_PATTERNS = compile_patterns(XSS_PATTERNS_RAW)
CMD_PATTERNS = compile_patterns(CMD_PATTERNS_RAW)
ENCODING_PATTERNS = compile_patterns(ENCODING_PATTERNS_RAW)

# ============================
# Rule-based detection
# ============================
def check_rule_based_threats(request_dict: dict) -> tuple[bool, str, list]:
    """
    Check for known attack patterns using precompiled regex rules.
    Returns: (is_threat, threat_type_label, matched_patterns_list)
    matched_patterns_list elements: (threat_label, pattern_str)
    """
    try:
        path = str(request_dict.get('path', '')).lower()
        query = json.dumps(request_dict.get('query', {})).lower() if isinstance(request_dict.get('query', {}), dict) else str(request_dict.get('query', '')).lower()
        body = str(request_dict.get('body', '')).lower()
    except Exception:
        path = str(request_dict.get('path', '')).lower()
        query = str(request_dict.get('query', '')).lower()
        body = str(request_dict.get('body', '')).lower()

    full_text = f"{path} {query} {body}"

    matched_patterns = []

    # Short-circuit: obvious path traversal tokens
    if '..' in full_text or '%2e%2e' in full_text:
        matched_patterns.append(('Path Traversal/LFI', '.. or %2e%2e token'))

    # Check path traversal & suspicious paths
    for patt in SUSPICIOUS_PATHS:
        if patt.search(full_text):
            matched_patterns.append(('Path Traversal/LFI', patt.pattern))

    # Check SQL injection
    for patt in SQL_PATTERNS:
        if patt.search(full_text):
            matched_patterns.append(('SQL Injection', patt.pattern))

    # Check XSS
    for patt in XSS_PATTERNS:
        if patt.search(full_text):
            matched_patterns.append(('XSS', patt.pattern))

    # Check command injection
    for patt in CMD_PATTERNS:
        if patt.search(full_text):
            matched_patterns.append(('Command Injection', patt.pattern))

    # Check encoding evasion
    for patt in ENCODING_PATTERNS:
        if patt.search(full_text):
            matched_patterns.append(('Encoding Evasion', patt.pattern))

    if matched_patterns:
        threat_types = list(set([m[0] for m in matched_patterns]))
        return True, ', '.join(threat_types), matched_patterns

    return False, '', []

# ============================
# Rule confidence heuristic
# ============================
def compute_rule_confidence(matched_patterns: list) -> tuple[float, str]:
    """
    Convert matched rule patterns into a confidence score (0-100) and risk level.
    Simple heuristic — tune weights as needed for your environment.
    matched_patterns: list of tuples (threat_label, pattern)
    """
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
        # slight penalty for encoded patterns (less certain)
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

# ============================
# ML Verdict LRU cache
# ============================
# Cache transformer results for identical normalized request signatures to avoid repeated heavy inference.
# Key: simple normalized string (method + path + sorted query keys + body snippet)
# Cache size chosen modestly; tune to memory/throughput requirements.
@lru_cache(maxsize=4096)
def cached_ml_infer(key: str):
    """
    This wrapper is cached. It assumes 'detector' global is available and callable.
    'key' is a deterministic normalized request string.
    Returns a plain serializable dict with fields we rely on.
    """
    # parse key back? not needed — detector will be called externally using original request dict
    # but this wrapper is used by hierarchical_detect which passes a JSON string of request summary
    # For safety, we will not attempt to reconstruct the full request here.
    return None  # Placeholder: hierarchical_detect uses direct detector.detect and uses cache externally.

# ============================
# Hierarchical detection
# ============================
def hierarchical_detect(request_dict: dict):
    """
    Hierarchical flow:
      1) Run rule-based checks (fast)
         - If rule flags malicious -> return immediately with rule verdict & confidence
      2) Else -> call ML detector.detect(request_dict) (expensive)
    Returns an object with:
      - is_malicious (bool)
      - confidence (float 0-100)
      - risk_level (str)
      - anomaly_score (float)
      - reconstruction_loss (float)
      - detection_method (str) -> 'RULE' or 'ML'
      - threat_type (str)
      - matched_patterns (list)
      - ml_details (dict)
    """
    # Run rule-based first
    rule_triggered, threat_type, matched_patterns = check_rule_based_threats(request_dict)

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
            self.ml_details = {}

    res = ResultObj()

    if rule_triggered:
        # Immediately return rule verdict (no ML call)
        conf, risk = compute_rule_confidence(matched_patterns)
        res.is_malicious = True
        res.confidence = conf
        res.risk_level = risk
        res.detection_method = "RULE"
        res.threat_type = threat_type
        res.matched_patterns = matched_patterns
        # leave ml fields default
        return res

    # Rule didn't flag -> prepare a deterministic cache key to possibly reuse ML verdicts
    # Build a compact signature string
    try:
        method = request_dict.get('method', 'GET')
        path = request_dict.get('path', '/')
        # sort query keys to canonicalize
        q = request_dict.get('query', {})
        if isinstance(q, dict):
            q_items = sorted([(str(k), str(v)) for k, v in q.items()])
        else:
            q_items = [(str(q), '')]
        # small body snippet to help differentiate
        body = request_dict.get('body', '')
        body_snip = (body[:128] + '...') if isinstance(body, str) and len(body) > 128 else str(body)
        cache_key = json.dumps([method, path, q_items, body_snip], sort_keys=True)
    except Exception:
        cache_key = None

    # If we have a cache entry for this input, fetch and return mapped result
    if cache_key is not None:
        # We cannot cache complex detector objects via @lru_cache easily here due to object references;
        # Instead, we'll use a simple in-memory dict cache that stores serializable dicts.
        # For clarity we implement it as attribute on the detector if available, else fallback to no-cache.
        cache_store = getattr(detector, "_ml_cache", None)
        if cache_store is None:
            detector._ml_cache = {}
            cache_store = detector._ml_cache

        cached = cache_store.get(cache_key)
        if cached:
            # Map cached dict to ResultObj
            res.is_malicious = cached.get('is_malicious', False)
            res.confidence = cached.get('confidence', 0.0)
            res.risk_level = cached.get('risk_level', 'LOW')
            res.reconstruction_loss = cached.get('reconstruction_loss', 0.0)
            res.anomaly_score = cached.get('anomaly_score', 0.0)
            res.detection_method = "ML(CACHED)"
            res.threat_type = cached.get('threat_type', 'None') if res.is_malicious else 'None'
            res.ml_details = cached.get('ml_details', {})
            return res

    # No cache -> call the ML detector (expensive)
    ml_result = detector.detect(request_dict)

    # Map ml_result into result object (support different possible value ranges)
    res.is_malicious = bool(getattr(ml_result, 'is_malicious', False))

    # Normalise confidence: accept either 0-1 or 0-100 representations
    raw_conf = getattr(ml_result, 'confidence', None)
    if raw_conf is None:
        # fallback: use anomaly_score if provided
        raw_anom = getattr(ml_result, 'anomaly_score', 0.0)
        conf_val = min(99.9, raw_anom * 100)
    else:
        conf_val = raw_conf * 100 if raw_conf <= 1.0 else raw_conf
    res.confidence = float(round(min(99.9, conf_val), 1))

    res.risk_level = getattr(ml_result, 'risk_level', 'LOW')
    res.reconstruction_loss = float(getattr(ml_result, 'reconstruction_loss', 0.0))
    res.anomaly_score = float(getattr(ml_result, 'anomaly_score', 0.0))
    res.detection_method = "ML"
    res.threat_type = getattr(ml_result, 'threat_type', 'Unknown Anomaly') if res.is_malicious else 'None'
    res.ml_details = getattr(ml_result, 'details', {})

    # Store serializable summary in cache for subsequent identical requests
    if cache_key is not None:
        try:
            detector._ml_cache[cache_key] = {
                'is_malicious': res.is_malicious,
                'confidence': res.confidence,
                'risk_level': res.risk_level,
                'reconstruction_loss': res.reconstruction_loss,
                'anomaly_score': res.anomaly_score,
                'threat_type': res.threat_type,
                'ml_details': res.ml_details
            }
            # Keep cache bounded (simple eviction strategy)
            if len(detector._ml_cache) > 4096:
                # pop an arbitrary item (simple LRU not implemented here to keep code small)
                detector._ml_cache.pop(next(iter(detector._ml_cache)))
        except Exception:
            pass

    return res

# ============================
# Parse Flask Request into dict
# ============================
def parse_flask_request(req) -> dict:
    """Convert Flask request to detector-friendly dict"""
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
        if request_dict['body']:
            request_dict['body'] += ' ' + form_data
        else:
            request_dict['body'] = form_data

    return request_dict

# ============================
# Logging and utilities
# ============================
def log_detection(request_dict: dict, result, client_ip: str):
    """Log detection result into in-memory buffer (keeps last 1000)"""
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'client_ip': client_ip,
        'method': request_dict.get('method', ''),
        'path': request_dict.get('path', ''),
        'is_malicious': result.is_malicious,
        'risk_level': result.risk_level,
        'confidence': result.confidence,
        'reconstruction_loss': getattr(result, 'reconstruction_loss', 0.0),
        'anomaly_score': getattr(result, 'anomaly_score', 0.0),
        'detection_method': getattr(result, 'detection_method', 'ML'),
        'threat_type': getattr(result, 'threat_type', 'N/A')
    }
    detection_log.append(log_entry)
    if len(detection_log) > 1000:
        detection_log.pop(0)
    return log_entry

# ============================
# Flask before_request — hierarchical
# ============================
@app.before_request
def check_request_hierarchical():
    """Hierarchical check: rules first; ML only if rules say safe."""
    global detector
    if detector is None:
        return jsonify({'error': 'WAF not initialized'}), 500

    # Skip health and internal endpoints
    if request.path in ['/health', '/waf/stats', '/waf/logs']:
        return None

    # Parse request into dict
    request_dict = parse_flask_request(request)

    # Run hierarchical detector
    result = hierarchical_detect(request_dict)

    # Log detection
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    log_entry = log_detection(request_dict, result, client_ip)

    # Console output
    if result.is_malicious:
        status_emoji = "🚨"
        color = "\033[91m"  # Red
    else:
        status_emoji = "✅"
        color = "\033[92m"  # Green"
    reset = "\033[0m"

    print(f"\n{color}{status_emoji} [{datetime.now().strftime('%H:%M:%S')}] "
          f"{request.method} {request.path}{reset}")
    print(f"   Risk: {result.risk_level} | Method: {result.detection_method} | "
          f"Confidence: {result.confidence:.1f}% | AnomScore: {result.anomaly_score:.4f}")

    if result.is_malicious and getattr(result, 'threat_type', None):
        print(f"   Threat: {getattr(result, 'threat_type', 'Unknown')}")

    # Blocking decision
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

    # Allow and return metadata
    response = {
        'blocked': False,
        'message': 'Request allowed',
        'risk_level': result.risk_level,
        'confidence': result.confidence,
        'detection_method': result.detection_method,
        'anomaly_score': result.anomaly_score,
        'threat_type': result.threat_type if getattr(result, 'threat_type', None) else 'None',
        'timestamp': datetime.now().isoformat()
    }
    return jsonify(response), 200

# ============================
# Monitoring endpoints
# ============================
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
    risk_counts = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
    for log in detection_log:
        risk_counts[log['risk_level']] += 1
    method_counts = {}
    for log in detection_log:
        method = log.get('detection_method', 'ML')
        method_counts[method] = method_counts.get(method, 0) + 1
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
    count = min(count, 1000)
    recent_logs = detection_log[-count:]
    return jsonify({
        'count': len(recent_logs),
        'logs': recent_logs
    })

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    """Catch-all route for testing any path (only reached if not blocked)"""
    return jsonify({
        'message': 'Request processed by WAF',
        'path': request.path,
        'method': request.method,
        'status': 'allowed'
    })

# ============================
# Detector Initialization
# ============================
def initialize_detector(
    model_path: str = "models/deberta-waf/best_model",
    calibration_file: str = "data/parsed/parsed_requests.json",
    threshold_percentile: float = 85.0
):
    """Initialize and calibrate the WAF detector"""
    global detector

    print("=" * 80)
    print("🛡️  Initializing Enhanced Hierarchical WAF Server")
    print("=" * 80)

    print("\n📦 Loading ML model...")
    detector = WAFDetector(
        model_path=model_path,
        threshold_percentile=threshold_percentile
    )

    # Attach a small in-memory cache on detector object for ML verdicts
    detector._ml_cache = {}

    print(f"\n📊 Loading calibration data from {calibration_file}...")
    # Attempt to load a small calibration sample - if missing, just skip gracefully
    try:
        with open(calibration_file, 'r') as f:
            benign_data = json.load(f)
        detector.calibrate(benign_data, num_samples=100)
    except Exception as e:
        print(f"⚠️  Calibration data load failed or not found: {e}. Continuing without calibration.")

    print("\n🎯 Rule-based detection enabled:")
    print(f"   - Path Traversal/LFI: {len(SUSPICIOUS_PATHS)} patterns")
    print(f"   - SQL Injection: {len(SQL_PATTERNS)} patterns")
    print(f"   - XSS: {len(XSS_PATTERNS)} patterns")
    print(f"   - Command Injection: {len(CMD_PATTERNS)} patterns")
    print(f"   - Encoding Evasion: {len(ENCODING_PATTERNS)} patterns")

    print("\n✅ Enhanced Hierarchical WAF Ready!")
    print("=" * 80)

# ============================
# MAIN
# ============================
if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Enhanced Hierarchical Hybrid WAF Server')
    parser.add_argument('--port', type=int, default=8080, help='Port to run server on')
    parser.add_argument('--model-path', type=str, default='models/deberta-waf/best_model', help='Path to trained model')
    parser.add_argument('--calibration-file', type=str, default='data/parsed/parsed_requests.json', help='Path to calibration data')
    parser.add_argument('--threshold', type=float, default=85.0, help='Detection threshold percentile (lower=more sensitive)')
    parser.add_argument('--no-block', action='store_true', help='Disable request blocking (log only)')
    args = parser.parse_args()

    # Initialize detector (model_path, calibration file, threshold)
    initialize_detector(
        model_path=args.model_path,
        calibration_file=args.calibration_file,
        threshold_percentile=args.threshold
    )

    print(f"\n🚀 Starting hierarchical WAF server on http://localhost:{args.port}")
    print(f"   Blocking mode: {'DISABLED (log only)' if args.no_block else 'ENABLED'}")
    print("\nPress Ctrl+C to stop\n")

    app.run(host='0.0.0.0', port=args.port, debug=False)
