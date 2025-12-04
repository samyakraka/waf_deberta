#!/usr/bin/env python3
"""
Real-Time WAF Log Monitor
Tails nginx log files and classifies each request in real-time using the DeBERTa WAF detector.

Features:
- Monitors multiple log files simultaneously (DVWA, Juice Shop, WebGoat)
- Streams logs to terminal in real-time with color-coded output
- Classifies each request as ATTACK or BENIGN
- Shows confidence scores and risk levels
- Can save detailed results to JSON file

Usage:
    python realtime_waf_monitor.py --model models/deberta-waf/best_model
    
Author: ISRO WAF Team
"""

import os
os.environ['TOKENIZERS_PARALLELISM'] = 'false'
os.environ['WANDB_DISABLED'] = 'true'

import sys
import time
import argparse
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional
import threading
from collections import deque

# Add src to path
sys.path.append(str(Path(__file__).parent))

from src.detector import WAFDetector
from src.log_parser import NginxLogParser


# ANSI color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
    # Risk level colors
    LOW = '\033[92m'      # Green
    MEDIUM = '\033[93m'   # Yellow
    HIGH = '\033[91m'     # Red
    CRITICAL = '\033[95m' # Magenta


class LogTailer:
    """Tails a log file and yields new lines as they are written"""
    
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.file = None
        
    def __enter__(self):
        # Wait for file to exist
        while not os.path.exists(self.filepath):
            time.sleep(0.1)
        
        self.file = open(self.filepath, 'r')
        # Seek to end of file
        self.file.seek(0, 2)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.file:
            self.file.close()
    
    def tail(self):
        """Generator that yields new lines"""
        while True:
            line = self.file.readline()
            if line:
                yield line
            else:
                time.sleep(0.1)


class RealtimeWAFMonitor:
    """Real-time WAF monitoring system"""
    
    def __init__(
        self,
        model_path: str,
        log_files: Dict[str, str],
        output_file: Optional[str] = None,
        calibration_data: Optional[str] = None,
    ):
        """
        Initialize monitor
        
        Args:
            model_path: Path to trained WAF model
            log_files: Dict mapping app name to log file path
            output_file: Optional JSON file to save results
            calibration_data: Optional path to calibration data for threshold tuning
        """
        self.log_files = log_files
        self.output_file = output_file
        
        # Initialize detector
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.HEADER}🛡️  Real-Time WAF Monitor - DeBERTa Transformer{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
        
        print(f"{Colors.OKCYAN}Loading WAF detector...{Colors.ENDC}")
        self.detector = WAFDetector(
            model_path=model_path,
            max_length=256,
            threshold_percentile=95.0  # Adjusted to better detect attacks
        )
        
        # Calibrate if data provided
        if calibration_data and os.path.exists(calibration_data):
            print(f"{Colors.OKCYAN}Calibrating detector with benign data...{Colors.ENDC}")
            with open(calibration_data, 'r') as f:
                benign_requests = json.load(f)
            
            print(f"{Colors.OKCYAN}Using {len(benign_requests)} calibration samples{Colors.ENDC}")
            
            self.detector.calibrate(benign_requests)  # Use all available samples for calibration
            print(f"{Colors.OKGREEN}✓ Calibration complete{Colors.ENDC}")
            print(f"{Colors.OKGREEN}  Threshold: {self.detector.anomaly_threshold:.4f}{Colors.ENDC}")
            print(f"{Colors.OKGREEN}  Mean Loss: {self.detector.baseline_stats['mean']:.4f}{Colors.ENDC}")
            print(f"{Colors.OKGREEN}  Std Dev: {self.detector.baseline_stats['std']:.4f}{Colors.ENDC}\n")
        else:
            print(f"{Colors.FAIL}⚠ ERROR: No calibration data provided!{Colors.ENDC}")
            print(f"{Colors.FAIL}  The detector needs calibration with benign traffic to work properly.{Colors.ENDC}")
            print(f"{Colors.FAIL}  Expected file: {calibration_data}{Colors.ENDC}\n")
            raise ValueError(f"Calibration data not found: {calibration_data}")
        
        # Initialize parser
        self.parser = NginxLogParser()
        
        # Statistics
        self.stats = {
            'total_requests': 0,
            'attacks_detected': 0,
            'benign_requests': 0,
            'parse_errors': 0,
            'by_app': {app: {'total': 0, 'attacks': 0, 'benign': 0} for app in log_files.keys()}
        }
        
        # Results buffer (for saving to file)
        self.results_buffer = deque(maxlen=1000)
        
        # Thread lock for thread-safe operations
        self.lock = threading.Lock()
        
        print(f"{Colors.OKGREEN}✓ Monitor initialized{Colors.ENDC}")
        print(f"{Colors.OKGREEN}✓ Watching {len(log_files)} log files{Colors.ENDC}\n")
        
        self._print_header()
    
    def _print_header(self):
        """Print monitoring header"""
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.HEADER}Monitoring Applications:{Colors.ENDC}")
        for app, logfile in self.log_files.items():
            print(f"  • {Colors.BOLD}{app}{Colors.ENDC}: {logfile}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
        print(f"{Colors.BOLD}{'Timestamp':<20} {'App':<12} {'Method':<8} {'Path':<30} {'Result':<15} {'Confidence':<12} {'Risk'}{Colors.ENDC}")
        print(f"{Colors.HEADER}{'-'*130}{Colors.ENDC}")
    
    def _get_risk_color(self, risk_level: str) -> str:
        """Get color for risk level"""
        risk_colors = {
            'LOW': Colors.LOW,
            'MEDIUM': Colors.MEDIUM,
            'HIGH': Colors.HIGH,
            'CRITICAL': Colors.CRITICAL,
        }
        return risk_colors.get(risk_level, Colors.ENDC)
    
    def _format_path(self, path: str, max_len: int = 30) -> str:
        """Truncate path if too long"""
        if len(path) > max_len:
            return path[:max_len-3] + '...'
        return path
    
    def classify_and_display(self, app_name: str, log_line: str):
        """Parse log line, classify, and display result"""
        try:
            # Parse log line
            parsed = self.parser.parse_line(log_line)
            if not parsed:
                with self.lock:
                    self.stats['parse_errors'] += 1
                return
            
            # Extract request for detector
            request = self.parser.extract_request_for_detector(parsed)
            
            # Classify
            result = self.detector.detect(request)
            
            # Update statistics
            with self.lock:
                self.stats['total_requests'] += 1
                self.stats['by_app'][app_name]['total'] += 1
                
                if result.is_malicious:
                    self.stats['attacks_detected'] += 1
                    self.stats['by_app'][app_name]['attacks'] += 1
                else:
                    self.stats['benign_requests'] += 1
                    self.stats['by_app'][app_name]['benign'] += 1
                
                # Store result
                self.results_buffer.append({
                    'timestamp': datetime.now().isoformat(),
                    'app': app_name,
                    'request': request,
                    'result': {
                        'is_malicious': result.is_malicious,
                        'confidence': result.confidence,
                        'risk_level': result.risk_level,
                        'anomaly_score': result.anomaly_score,
                    }
                })
            
            # Display
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            method = request['method']
            path = self._format_path(request['path'], 30)
            
            # Color-code result
            if result.is_malicious:
                result_text = f"{Colors.FAIL}🚨 ATTACK{Colors.ENDC}"
            else:
                result_text = f"{Colors.OKGREEN}✓ BENIGN{Colors.ENDC}"
            
            confidence = f"{result.confidence:.1%}"
            risk_color = self._get_risk_color(result.risk_level)
            risk_text = f"{risk_color}{result.risk_level}{Colors.ENDC}"
            
            print(f"{timestamp:<20} {app_name:<12} {method:<8} {path:<30} {result_text:<25} {confidence:<12} {risk_text}")
            
            # Save periodically
            if self.output_file and len(self.results_buffer) % 50 == 0:
                self._save_results()
        
        except Exception as e:
            print(f"{Colors.FAIL}Error processing log: {e}{Colors.ENDC}")
    
    def _save_results(self):
        """Save buffered results to file"""
        if not self.output_file:
            return
        
        try:
            with open(self.output_file, 'w') as f:
                json.dump(list(self.results_buffer), f, indent=2)
        except Exception as e:
            print(f"{Colors.WARNING}Warning: Could not save results: {e}{Colors.ENDC}")
    
    def monitor_log(self, app_name: str, log_path: str):
        """Monitor a single log file (runs in separate thread)"""
        try:
            with LogTailer(log_path) as tailer:
                for line in tailer.tail():
                    self.classify_and_display(app_name, line)
        except KeyboardInterrupt:
            pass
        except Exception as e:
            print(f"{Colors.FAIL}Error monitoring {app_name}: {e}{Colors.ENDC}")
    
    def start(self):
        """Start monitoring all log files"""
        threads = []
        
        # Create a thread for each log file
        for app_name, log_path in self.log_files.items():
            thread = threading.Thread(
                target=self.monitor_log,
                args=(app_name, log_path),
                daemon=True
            )
            thread.start()
            threads.append(thread)
        
        try:
            # Print statistics periodically
            while True:
                time.sleep(10)
                self._print_stats()
        
        except KeyboardInterrupt:
            print(f"\n\n{Colors.WARNING}Shutting down monitor...{Colors.ENDC}")
            self._save_results()
            self._print_final_stats()
    
    def _print_stats(self):
        """Print current statistics"""
        with self.lock:
            print(f"\n{Colors.OKCYAN}{'='*80}{Colors.ENDC}")
            print(f"{Colors.OKCYAN}Statistics (Total: {self.stats['total_requests']} requests){Colors.ENDC}")
            print(f"  Attacks: {Colors.FAIL}{self.stats['attacks_detected']}{Colors.ENDC} | "
                  f"Benign: {Colors.OKGREEN}{self.stats['benign_requests']}{Colors.ENDC} | "
                  f"Parse Errors: {self.stats['parse_errors']}")
            print(f"{Colors.OKCYAN}{'='*80}{Colors.ENDC}\n")
    
    def _print_final_stats(self):
        """Print final statistics on shutdown"""
        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.HEADER}Final Statistics{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}")
        
        with self.lock:
            print(f"\n{Colors.BOLD}Overall:{Colors.ENDC}")
            print(f"  Total Requests: {self.stats['total_requests']}")
            print(f"  Attacks Detected: {Colors.FAIL}{self.stats['attacks_detected']}{Colors.ENDC}")
            print(f"  Benign Requests: {Colors.OKGREEN}{self.stats['benign_requests']}{Colors.ENDC}")
            print(f"  Parse Errors: {self.stats['parse_errors']}")
            
            if self.stats['total_requests'] > 0:
                attack_rate = self.stats['attacks_detected'] / self.stats['total_requests'] * 100
                print(f"  Attack Rate: {attack_rate:.2f}%")
            
            print(f"\n{Colors.BOLD}By Application:{Colors.ENDC}")
            for app, stats in self.stats['by_app'].items():
                if stats['total'] > 0:
                    attack_rate = stats['attacks'] / stats['total'] * 100
                    print(f"  {app}:")
                    print(f"    Total: {stats['total']}, "
                          f"Attacks: {Colors.FAIL}{stats['attacks']}{Colors.ENDC}, "
                          f"Benign: {Colors.OKGREEN}{stats['benign']}{Colors.ENDC}, "
                          f"Attack Rate: {attack_rate:.2f}%")
        
        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")


def main():
    parser = argparse.ArgumentParser(
        description='Real-time WAF monitoring with DeBERTa classifier'
    )
    parser.add_argument(
        '--model',
        type=str,
        default='models/deberta-waf/best_model',
        help='Path to trained WAF model directory'
    )
    parser.add_argument(
        '--logs-dir',
        type=str,
        default='nginx/logs',
        help='Directory containing nginx log files'
    )
    parser.add_argument(
        '--output',
        type=str,
        default=None,
        help='Output JSON file for results (optional)'
    )
    parser.add_argument(
        '--calibration',
        type=str,
        default=None,
        help='Path to benign requests JSON for calibration (optional)'
    )
    
    args = parser.parse_args()
    
    # Define log files to monitor
    logs_dir = Path(args.logs_dir)
    log_files = {
        'DVWA': str(logs_dir / 'dvwa-access.log'),
        'JuiceShop': str(logs_dir / 'juiceshop-access.log'),
        'WebGoat': str(logs_dir / 'webgoat-access.log'),
    }
    
    # Check if model exists
    if not os.path.exists(args.model):
        print(f"{Colors.FAIL}Error: Model not found at {args.model}{Colors.ENDC}")
        print(f"{Colors.WARNING}Please train the model first or specify correct path{Colors.ENDC}")
        sys.exit(1)
    
    # Create monitor
    monitor = RealtimeWAFMonitor(
        model_path=args.model,
        log_files=log_files,
        output_file=args.output,
        calibration_data=args.calibration,
    )
    
    # Start monitoring
    print(f"{Colors.OKGREEN}Starting real-time monitoring...{Colors.ENDC}")
    print(f"{Colors.OKCYAN}Press Ctrl+C to stop{Colors.ENDC}\n")
    
    monitor.start()


if __name__ == '__main__':
    main()
