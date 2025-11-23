"""
Test Script for DeBERTa-based WAF Model
Tests detection capability on both benign and malicious payloads
Suitable for Grand Finale evaluation by judges
Author: ISRO WAF Team
"""

import os
os.environ['TOKENIZERS_PARALLELISM'] = 'false'

import json
import sys
import argparse
from pathlib import Path
from datetime import datetime
from typing import List, Dict
import torch

# Add src to path
sys.path.append(str(Path(__file__).parent))

from src.detector import WAFDetector, DetectionResult


class WAFTester:
    """
    Testing framework for WAF evaluation
    Designed for Grand Finale judging
    """
    
    def __init__(
        self,
        model_path: str = "models/deberta-waf/best_model",
        calibration_file: str = "data/parsed/parsed_requests.json"
    ):
        """
        Initialize tester
        
        Args:
            model_path: Path to trained model
            calibration_file: Path to benign requests for calibration
        """
        self.model_path = model_path
        self.calibration_file = calibration_file
        self.detector = None
        
        print("=" * 80)
        print("🛡️  DeBERTa-based WAF Testing Framework")
        print("=" * 80)
    
    def load_detector(self, threshold_percentile: float = 95.0) -> None:
        """
        Load and calibrate detector
        
        Args:
            threshold_percentile: Detection threshold percentile (95-99 recommended)
        """
        print("\n📦 Loading trained model...")
        self.detector = WAFDetector(
            model_path=self.model_path,
            threshold_percentile=threshold_percentile
        )
        
        # Load calibration data
        print(f"\n📊 Loading calibration data from {self.calibration_file}...")
        with open(self.calibration_file, 'r') as f:
            benign_data = json.load(f)
        
        # Calibrate detector
        self.detector.calibrate(benign_data, num_samples=100)
        
        print("\n✅ Detector ready for testing!")
    
    def test_single_request(
        self,
        request: Dict,
        show_details: bool = True
    ) -> DetectionResult:
        """
        Test a single request
        
        Args:
            request: Request dictionary
            show_details: Print detailed results
            
        Returns:
            DetectionResult
        """
        if self.detector is None:
            raise ValueError("Detector not loaded! Call load_detector() first.")
        
        result = self.detector.detect(request)
        
        if show_details:
            self._print_detection_result(request, result)
        
        return result
    
    def test_batch_requests(
        self,
        requests: List[Dict],
        labels: List[int] = None,
        output_file: str = None
    ) -> Dict:
        """
        Test multiple requests and generate report
        
        Args:
            requests: List of request dictionaries
            labels: Optional ground truth labels (0=benign, 1=malicious)
            output_file: Optional file to save report
            
        Returns:
            Report dictionary
        """
        if self.detector is None:
            raise ValueError("Detector not loaded! Call load_detector() first.")
        
        print(f"\n🧪 Testing {len(requests)} requests...")
        results = self.detector.batch_detect(requests)
        
        # Generate report
        report = self.detector.generate_report(results, requests)
        
        # Add ground truth comparison if labels provided
        if labels is not None:
            report['evaluation'] = self._compute_metrics(results, labels)
        
        # Add timestamp
        report['timestamp'] = datetime.now().isoformat()
        report['model_path'] = self.model_path
        
        # Print summary
        self._print_summary(report)
        
        # Save report if requested
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n💾 Report saved to {output_file}")
        
        return report
    
    def test_from_file(
        self,
        test_file: str,
        output_file: str = None
    ) -> Dict:
        """
        Test requests from a JSON file
        
        Args:
            test_file: Path to JSON file with requests
            output_file: Optional output file for report
            
        Returns:
            Report dictionary
        """
        print(f"\n📂 Loading test data from {test_file}...")
        
        with open(test_file, 'r') as f:
            test_data = json.load(f)
        
        # Support different formats
        if isinstance(test_data, list):
            requests = test_data
            labels = None
        elif isinstance(test_data, dict):
            requests = test_data.get('requests', [])
            labels = test_data.get('labels', None)
        else:
            raise ValueError("Invalid test file format")
        
        print(f"✓ Loaded {len(requests)} requests")
        
        return self.test_batch_requests(requests, labels, output_file)
    
    def test_curl_payload(self, curl_command: str) -> DetectionResult:
        """
        Test a payload from a curl command
        
        Args:
            curl_command: curl command string
            
        Returns:
            DetectionResult
        """
        request = self._parse_curl_command(curl_command)
        return self.test_single_request(request)
    
    def _parse_curl_command(self, curl_command: str) -> Dict:
        """
        Parse curl command into request dictionary
        
        Args:
            curl_command: curl command string
            
        Returns:
            Request dictionary
        """
        # Simple parser (can be enhanced)
        request = {
            'method': 'GET',
            'path': '/',
            'headers': {},
            'query': {},
            'body': ''
        }
        
        # Extract URL
        parts = curl_command.split()
        for i, part in enumerate(parts):
            if part.startswith('http'):
                url = part.strip("'\"")
                if '?' in url:
                    path, query_string = url.split('?', 1)
                    request['path'] = path.split('://')[-1].split('/', 1)[-1] if '/' in path else '/'
                    # Parse query string
                    for param in query_string.split('&'):
                        if '=' in param:
                            key, val = param.split('=', 1)
                            request['query'][key] = val
                else:
                    request['path'] = url.split('://')[-1].split('/', 1)[-1] if '/' in url else '/'
            
            # Extract method
            elif part in ['-X', '--request']:
                if i + 1 < len(parts):
                    request['method'] = parts[i + 1].upper()
            
            # Extract headers
            elif part in ['-H', '--header']:
                if i + 1 < len(parts):
                    header = parts[i + 1].strip("'\"")
                    if ':' in header:
                        key, val = header.split(':', 1)
                        request['headers'][key.lower()] = val.strip()
            
            # Extract data
            elif part in ['-d', '--data']:
                if i + 1 < len(parts):
                    request['body'] = parts[i + 1].strip("'\"")
                    if request['method'] == 'GET':
                        request['method'] = 'POST'
        
        return request
    
    def _compute_metrics(
        self,
        results: List[DetectionResult],
        labels: List[int]
    ) -> Dict:
        """
        Compute evaluation metrics
        
        Args:
            results: Detection results
            labels: Ground truth (0=benign, 1=malicious)
            
        Returns:
            Metrics dictionary
        """
        predictions = [1 if r.is_malicious else 0 for r in results]
        
        tp = sum(1 for p, l in zip(predictions, labels) if p == 1 and l == 1)
        tn = sum(1 for p, l in zip(predictions, labels) if p == 0 and l == 0)
        fp = sum(1 for p, l in zip(predictions, labels) if p == 1 and l == 0)
        fn = sum(1 for p, l in zip(predictions, labels) if p == 0 and l == 1)
        
        accuracy = (tp + tn) / len(labels) if len(labels) > 0 else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        
        return {
            'accuracy': float(accuracy),
            'precision': float(precision),
            'recall': float(recall),
            'f1_score': float(f1),
            'true_positives': tp,
            'true_negatives': tn,
            'false_positives': fp,
            'false_negatives': fn,
            'total_samples': len(labels),
            'confusion_matrix': {
                'TP': tp,
                'TN': tn,
                'FP': fp,
                'FN': fn
            }
        }
    
    def _print_detection_result(
        self,
        request: Dict,
        result: DetectionResult
    ) -> None:
        """Print formatted detection result"""
        print("\n" + "─" * 80)
        print("🔍 DETECTION RESULT")
        print("─" * 80)
        
        # Request info
        print(f"\n📋 Request:")
        print(f"   Method: {request.get('method', 'N/A')}")
        print(f"   Path: {request.get('path', 'N/A')}")
        if request.get('query'):
            print(f"   Query: {request['query']}")
        
        # Detection result
        status_emoji = "🚨" if result.is_malicious else "✅"
        status_text = "MALICIOUS" if result.is_malicious else "BENIGN"
        
        print(f"\n{status_emoji} Status: {status_text}")
        print(f"   Risk Level: {result.risk_level}")
        print(f"   Confidence: {result.confidence:.2f}%")
        print(f"   Reconstruction Loss: {result.reconstruction_loss:.4f}")
        print(f"   Anomaly Score: {result.anomaly_score:.4f}")
        print(f"   Threshold: {result.details['threshold']:.4f}")
        
        print("─" * 80)
    
    def _print_summary(self, report: Dict) -> None:
        """Print report summary"""
        summary = report['summary']
        
        print("\n" + "=" * 80)
        print("📊 TEST SUMMARY")
        print("=" * 80)
        
        print(f"\nTotal Requests: {summary['total_requests']}")
        print(f"Malicious Detected: {summary['malicious_detected']} ({summary['detection_rate']:.2f}%)")
        print(f"Benign Detected: {summary['benign_detected']}")
        
        print(f"\nAverage Metrics:")
        print(f"   Reconstruction Loss: {summary['avg_reconstruction_loss']:.4f}")
        print(f"   Confidence: {summary['avg_confidence']:.2f}%")
        print(f"   Anomaly Score: {summary['avg_anomaly_score']:.4f}")
        
        print(f"\nRisk Distribution:")
        for level, count in report['risk_distribution'].items():
            print(f"   {level}: {count}")
        
        # Print evaluation metrics if available
        if 'evaluation' in report:
            eval_metrics = report['evaluation']
            print(f"\n🎯 Evaluation Metrics:")
            print(f"   Accuracy: {eval_metrics['accuracy']:.4f}")
            print(f"   Precision: {eval_metrics['precision']:.4f}")
            print(f"   Recall: {eval_metrics['recall']:.4f}")
            print(f"   F1-Score: {eval_metrics['f1_score']:.4f}")
            
            print(f"\nConfusion Matrix:")
            cm = eval_metrics['confusion_matrix']
            print(f"   True Positives: {cm['TP']}")
            print(f"   True Negatives: {cm['TN']}")
            print(f"   False Positives: {cm['FP']}")
            print(f"   False Negatives: {cm['FN']}")
        
        print("=" * 80)


def main():
    """Main testing interface"""
    parser = argparse.ArgumentParser(
        description="Test DeBERTa-based WAF Model",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test from file
  python test_model.py --test-file test_payloads.json --output report.json
  
  # Interactive testing
  python test_model.py --interactive
  
  # Test with custom threshold
  python test_model.py --test-file payloads.json --threshold 99
        """
    )
    
    parser.add_argument(
        '--model',
        default='models/deberta-waf/best_model',
        help='Path to trained model directory'
    )
    
    parser.add_argument(
        '--calibration',
        default='data/parsed/parsed_requests.json',
        help='Path to benign requests for calibration'
    )
    
    parser.add_argument(
        '--test-file',
        help='JSON file with test requests'
    )
    
    parser.add_argument(
        '--output',
        help='Output file for test report (JSON)'
    )
    
    parser.add_argument(
        '--threshold',
        type=float,
        default=95.0,
        help='Detection threshold percentile (90-99, default: 95)'
    )
    
    parser.add_argument(
        '--interactive',
        action='store_true',
        help='Interactive testing mode'
    )
    
    args = parser.parse_args()
    
    # Initialize tester
    tester = WAFTester(
        model_path=args.model,
        calibration_file=args.calibration
    )
    
    # Load and calibrate detector
    tester.load_detector(threshold_percentile=args.threshold)
    
    # Test mode
    if args.test_file:
        # Batch testing from file
        tester.test_from_file(args.test_file, args.output)
    
    elif args.interactive:
        # Interactive mode
        print("\n🎮 Interactive Testing Mode")
        print("=" * 80)
        print("Enter 'quit' to exit")
        print("Enter 'file <path>' to test from file")
        print("Or paste JSON request directly")
        print("=" * 80)
        
        while True:
            print("\n📝 Enter request (or command):")
            try:
                user_input = input("> ").strip()
                
                if user_input.lower() == 'quit':
                    break
                
                elif user_input.lower().startswith('file '):
                    file_path = user_input[5:].strip()
                    tester.test_from_file(file_path)
                
                else:
                    # Try to parse as JSON
                    request = json.loads(user_input)
                    tester.test_single_request(request)
            
            except json.JSONDecodeError:
                print("❌ Invalid JSON format")
            except Exception as e:
                print(f"❌ Error: {e}")
    
    else:
        # No test specified, show help
        print("\n⚠️  No test specified. Use --test-file or --interactive")
        parser.print_help()


if __name__ == "__main__":
    main()
