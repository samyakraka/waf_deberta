"""
Real-time WAF Testing Server
Receives HTTP requests and detects malicious payloads in real-time
Suitable for Grand Finale live demonstration
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


def initialize_detector(
    model_path: str = "models_30k/deberta-waf/best_model",
    calibration_file: str = "data/parsed/parsed_requests.json",
    threshold_percentile: float = 80.0  # CHANGED: Lower threshold for better detection (was 95.0)
):
    """Initialize and calibrate the WAF detector"""
    global detector
    
    print("=" * 80)
    print("🛡️  Initializing DeBERTa-based WAF Server")
    print("=" * 80)
    
    print("\n📦 Loading model...")
    detector = WAFDetector(
        model_path=model_path,
        threshold_percentile=threshold_percentile
    )
    
    print(f"\n📊 Loading calibration data from {calibration_file}...")
    with open(calibration_file, 'r') as f:
        benign_data = json.load(f)
    
    detector.calibrate(benign_data, num_samples=100)
    
    print("\n✅ WAF Server Ready!")
    print("=" * 80)


def parse_flask_request(req) -> dict:
    """Convert Flask request to detector format"""
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
            request_dict['body'] = req.data.decode('utf-8')
        except:
            request_dict['body'] = str(req.data)
    
    # Try to parse JSON body
    if req.is_json:
        try:
            request_dict['body'] = json.dumps(req.get_json())
        except:
            pass
    
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
        'anomaly_score': result.anomaly_score
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
    
    # Detect
    result = detector.detect(request_dict)
    
    # Log detection
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    log_entry = log_detection(request_dict, result, client_ip)
    
    # Print to console
    status_emoji = "🚨" if result.is_malicious else "✅"
    print(f"\n{status_emoji} [{datetime.now().strftime('%H:%M:%S')}] "
          f"{request.method} {request.path} - "
          f"{result.risk_level} (Loss: {result.reconstruction_loss:.4f})")
    
    # Block if malicious (optional - can be configured)
    if result.is_malicious and result.risk_level in ['HIGH', 'CRITICAL']:
        response = {
            'blocked': True,
            'reason': 'Malicious request detected',
            'risk_level': result.risk_level,
            'confidence': result.confidence,
            'anomaly_score': result.anomaly_score,
            'timestamp': datetime.now().isoformat()
        }
        return jsonify(response), 403
    
    return None


# ============================================================================
# APPLICATION ROUTES (These are protected by the WAF)
# ============================================================================

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'waf_active': detector is not None})


@app.route('/')
def index():
    """Landing page"""
    return jsonify({
        'message': 'DeBERTa-based WAF Testing Server',
        'version': '1.0',
        'endpoints': {
            '/health': 'Health check',
            '/waf/stats': 'WAF statistics',
            '/waf/logs': 'Detection logs',
            '/api/*': 'Test API endpoints'
        }
    })


@app.route('/api/test', methods=['GET', 'POST', 'PUT', 'DELETE'])
def api_test():
    """Test API endpoint"""
    return jsonify({
        'success': True,
        'method': request.method,
        'message': 'Request passed WAF protection'
    })


@app.route('/api/users', methods=['GET', 'POST'])
def api_users():
    """Simulated users endpoint"""
    if request.method == 'GET':
        return jsonify({
            'users': [
                {'id': 1, 'name': 'John Doe'},
                {'id': 2, 'name': 'Jane Smith'}
            ]
        })
    else:
        data = request.get_json() if request.is_json else {}
        return jsonify({
            'success': True,
            'message': 'User created',
            'data': data
        }), 201


@app.route('/api/products')
def api_products():
    """Simulated products endpoint"""
    return jsonify({
        'products': [
            {'id': 1, 'name': 'Laptop', 'price': 999.99},
            {'id': 2, 'name': 'Mouse', 'price': 29.99}
        ]
    })


@app.route('/search')
def search():
    """Search endpoint (vulnerable to XSS in normal apps)"""
    query = request.args.get('q', '')
    return jsonify({
        'query': query,
        'results': ['Result 1', 'Result 2']
    })


@app.route('/login', methods=['POST'])
def login():
    """Login endpoint (vulnerable to SQL injection in normal apps)"""
    data = request.get_json() if request.is_json else {}
    return jsonify({
        'success': True,
        'message': 'Login attempt processed'
    })


# ============================================================================
# WAF MONITORING ROUTES
# ============================================================================

@app.route('/waf/stats')
def waf_stats():
    """Get WAF statistics"""
    if not detection_log:
        return jsonify({
            'total_requests': 0,
            'malicious_count': 0,
            'benign_count': 0
        })
    
    total = len(detection_log)
    malicious = sum(1 for log in detection_log if log['is_malicious'])
    benign = total - malicious
    
    # Risk level distribution
    risk_dist = {
        'LOW': sum(1 for log in detection_log if log['risk_level'] == 'LOW'),
        'MEDIUM': sum(1 for log in detection_log if log['risk_level'] == 'MEDIUM'),
        'HIGH': sum(1 for log in detection_log if log['risk_level'] == 'HIGH'),
        'CRITICAL': sum(1 for log in detection_log if log['risk_level'] == 'CRITICAL')
    }
    
    stats = {
        'total_requests': total,
        'malicious_count': malicious,
        'benign_count': benign,
        'detection_rate': (malicious / total * 100) if total > 0 else 0,
        'risk_distribution': risk_dist,
        'threshold': float(detector.anomaly_threshold) if detector else None,
        'model_loaded': detector is not None
    }
    
    return jsonify(stats)


@app.route('/waf/logs')
def waf_logs():
    """Get detection logs"""
    limit = request.args.get('limit', 50, type=int)
    risk_filter = request.args.get('risk', None)
    
    logs = detection_log[-limit:]
    
    if risk_filter:
        logs = [log for log in logs if log['risk_level'] == risk_filter.upper()]
    
    return jsonify({
        'count': len(logs),
        'logs': logs
    })


@app.route('/waf/export')
def waf_export():
    """Export all logs as JSON"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"waf_logs_{timestamp}.json"
    
    return Response(
        json.dumps(detection_log, indent=2),
        mimetype='application/json',
        headers={'Content-Disposition': f'attachment;filename={filename}'}
    )


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="WAF Testing Server")
    
    parser.add_argument(
        '--model',
        default='models_30k/deberta-waf/best_model',
        help='Path to trained model'
    )
    
    parser.add_argument(
        '--calibration',
        default='data/parsed/parsed_requests.json',
        help='Path to calibration data'
    )
    
    parser.add_argument(
        '--threshold',
        type=float,
        default=95.0,
        help='Detection threshold percentile'
    )
    
    parser.add_argument(
        '--host',
        default='0.0.0.0',
        help='Server host'
    )
    
    parser.add_argument(
        '--port',
        type=int,
        default=5000,
        help='Server port'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug mode'
    )
    
    args = parser.parse_args()
    
    # Initialize detector
    initialize_detector(
        model_path=args.model,
        calibration_file=args.calibration,
        threshold_percentile=args.threshold
    )
    
    # Start server
    print(f"\n🚀 Starting server on {args.host}:{args.port}")
    print(f"\n📝 Test endpoints:")
    print(f"   http://{args.host}:{args.port}/")
    print(f"   http://{args.host}:{args.port}/api/test")
    print(f"   http://{args.host}:{args.port}/search?q=test")
    print(f"\n📊 Monitoring:")
    print(f"   http://{args.host}:{args.port}/waf/stats")
    print(f"   http://{args.host}:{args.port}/waf/logs")
    print(f"\n🛑 Press Ctrl+C to stop\n")
    
    app.run(
        host=args.host,
        port=args.port,
        debug=args.debug
    )


if __name__ == "__main__":
    main()
