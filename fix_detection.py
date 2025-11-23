"""
Quick Fix Script for WAF Detection Issues
Provides multiple solutions to improve malicious request detection
Author: ISRO WAF Team
"""

import json
import sys
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).parent))

from src.detector import WAFDetector


def solution_1_lower_threshold():
    """
    Solution 1: Lower the detection threshold
    Instead of 95th percentile, use 85th or 90th percentile
    This will make the detector more sensitive
    """
    print("=" * 80)
    print("Solution 1: Lower Detection Threshold")
    print("=" * 80)
    
    # Initialize detector with lower threshold
    detector = WAFDetector(
        model_path="models/deberta-waf/best_model",
        threshold_percentile=85.0  # Was 95.0, now 85.0 (more sensitive)
    )
    
    # Calibrate
    with open("data/parsed/parsed_requests.json", 'r') as f:
        benign_data = json.load(f)
    
    detector.calibrate(benign_data, num_samples=100)
    
    # Test on malicious samples
    test_requests = [
        {'method': 'GET', 'path': '/etc/passwd', 'headers': {}, 'query': {}, 'body': ''},
        {'method': 'GET', 'path': '/admin', 'headers': {}, 'query': {}, 'body': ''},
        {'method': 'GET', 'path': '/', 'headers': {}, 'query': {}, 'body': ''},
        {'method': 'GET', 'path': '/../../etc/passwd', 'headers': {}, 'query': {}, 'body': ''},
        {'method': 'GET', 'path': '/search', 'headers': {}, 'query': {'q': "' OR '1'='1"}, 'body': ''},
    ]
    
    print("\n📊 Testing with 85th percentile threshold:")
    for req in test_requests:
        result = detector.detect(req)
        status = "🚨 MALICIOUS" if result.is_malicious else "✅ BENIGN"
        print(f"{status} | {req['method']} {req['path']} | "
              f"Loss: {result.reconstruction_loss:.4f} | "
              f"Risk: {result.risk_level} | Conf: {result.confidence:.1f}%")
    
    return detector


def solution_2_lower_to_75():
    """
    Solution 2: Even lower threshold (75th percentile)
    Very sensitive - will catch more attacks but may have false positives
    """
    print("\n" + "=" * 80)
    print("Solution 2: Very Low Threshold (75th percentile)")
    print("=" * 80)
    
    detector = WAFDetector(
        model_path="models/deberta-waf/best_model",
        threshold_percentile=75.0  # Very sensitive
    )
    
    with open("data/parsed/parsed_requests.json", 'r') as f:
        benign_data = json.load(f)
    
    detector.calibrate(benign_data, num_samples=100)
    
    test_requests = [
        {'method': 'GET', 'path': '/etc/passwd', 'headers': {}, 'query': {}, 'body': ''},
        {'method': 'GET', 'path': '/../../etc/passwd', 'headers': {}, 'query': {}, 'body': ''},
        {'method': 'GET', 'path': '/admin/../../../etc/shadow', 'headers': {}, 'query': {}, 'body': ''},
        {'method': 'GET', 'path': '/search', 'headers': {}, 'query': {'q': "' OR '1'='1"}, 'body': ''},
        {'method': 'POST', 'path': '/login', 'headers': {}, 'query': {}, 'body': '{"user": "admin\' OR \'1\'=\'1"}'},
    ]
    
    print("\n📊 Testing with 75th percentile threshold:")
    for req in test_requests:
        result = detector.detect(req)
        status = "🚨 MALICIOUS" if result.is_malicious else "✅ BENIGN"
        print(f"{status} | {req['method']} {req['path']} | "
              f"Loss: {result.reconstruction_loss:.4f} | "
              f"Risk: {result.risk_level} | Conf: {result.confidence:.1f}%")
    
    return detector


def solution_3_hybrid_detection():
    """
    Solution 3: Hybrid approach - combine ML with simple rule-based checks
    Use ML for sophisticated attacks, rules for obvious ones
    """
    print("\n" + "=" * 80)
    print("Solution 3: Hybrid ML + Rule-Based Detection")
    print("=" * 80)
    
    # Common attack patterns
    SUSPICIOUS_PATTERNS = [
        '/etc/passwd', '/etc/shadow', '/etc/hosts',
        '../', '..\\',
        '<script', 'javascript:',
        'union select', 'or 1=1', "' or '1'='1",
        'cmd.exe', '/bin/bash', '/bin/sh',
        '%00', '%0d%0a',
        'base64', 'eval(', 'exec(',
    ]
    
    def hybrid_detect(detector, request):
        """Check both ML and rules"""
        # ML detection
        ml_result = detector.detect(request)
        
        # Rule-based check
        path = request.get('path', '').lower()
        query = str(request.get('query', {})).lower()
        body = str(request.get('body', '')).lower()
        
        full_text = f"{path} {query} {body}"
        
        rule_triggered = any(pattern.lower() in full_text for pattern in SUSPICIOUS_PATTERNS)
        
        # Combine results
        is_malicious = ml_result.is_malicious or rule_triggered
        
        if rule_triggered and not ml_result.is_malicious:
            # Rule caught it but ML didn't - upgrade confidence
            confidence = 90.0
            risk_level = "HIGH"
            detection_method = "RULE"
        elif ml_result.is_malicious:
            confidence = ml_result.confidence
            risk_level = ml_result.risk_level
            detection_method = "ML"
        else:
            confidence = ml_result.confidence
            risk_level = ml_result.risk_level
            detection_method = "CLEAN"
        
        return {
            'is_malicious': is_malicious,
            'confidence': confidence,
            'risk_level': risk_level,
            'reconstruction_loss': ml_result.reconstruction_loss,
            'detection_method': detection_method,
            'rule_triggered': rule_triggered
        }
    
    # Initialize ML detector with moderate threshold
    detector = WAFDetector(
        model_path="models/deberta-waf/best_model",
        threshold_percentile=90.0
    )
    
    with open("data/parsed/parsed_requests.json", 'r') as f:
        benign_data = json.load(f)
    
    detector.calibrate(benign_data, num_samples=100)
    
    # Test
    test_requests = [
        {'method': 'GET', 'path': '/etc/passwd', 'headers': {}, 'query': {}, 'body': ''},
        {'method': 'GET', 'path': '/../../etc/passwd', 'headers': {}, 'query': {}, 'body': ''},
        {'method': 'GET', 'path': '/search', 'headers': {}, 'query': {'q': "' OR '1'='1"}, 'body': ''},
        {'method': 'GET', 'path': '/api/users', 'headers': {}, 'query': {}, 'body': ''},
        {'method': 'POST', 'path': '/login', 'headers': {}, 'query': {}, 'body': '{"user": "admin"}'},
    ]
    
    print("\n📊 Testing hybrid detection:")
    for req in test_requests:
        result = hybrid_detect(detector, req)
        status = "🚨 MALICIOUS" if result['is_malicious'] else "✅ BENIGN"
        print(f"{status} | {req['method']} {req['path']} | "
              f"Loss: {result['reconstruction_loss']:.4f} | "
              f"Risk: {result['risk_level']} | "
              f"Method: {result['detection_method']}")
    
    return detector, hybrid_detect


if __name__ == "__main__":
    print("\n🔧 WAF Detection Fix Script\n")
    print("This script demonstrates 3 solutions:\n")
    print("1. Lower threshold to 85th percentile (moderate)")
    print("2. Lower threshold to 75th percentile (sensitive)")
    print("3. Hybrid ML + rule-based detection (recommended)\n")
    
    choice = input("Select solution to test (1/2/3 or 'all'): ").strip()
    
    if choice == '1' or choice == 'all':
        solution_1_lower_threshold()
    
    if choice == '2' or choice == 'all':
        solution_2_lower_to_75()
    
    if choice == '3' or choice == 'all':
        solution_3_hybrid_detection()
    
    print("\n" + "=" * 80)
    print("✅ Testing Complete!")
    print("=" * 80)
