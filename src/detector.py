"""
Anomaly Detection Module for DeBERTa-based WAF
Detects malicious payloads using reconstruction loss from MLM
Author: ISRO WAF Team
"""

# CRITICAL: Set environment variables BEFORE any imports
import os
os.environ['TOKENIZERS_PARALLELISM'] = 'false'
os.environ['OMP_NUM_THREADS'] = '1'
os.environ['MKL_NUM_THREADS'] = '1'
os.environ['NUMEXPR_NUM_THREADS'] = '1'
os.environ['OPENBLAS_NUM_THREADS'] = '1'
os.environ['ABSL_MIN_LOG_LEVEL'] = '3'
os.environ['PYTORCH_ENABLE_MPS_FALLBACK'] = '1'

import warnings
warnings.filterwarnings('ignore')

import json
import torch
import torch.nn.functional as F
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
import numpy as np
from transformers import AutoModelForMaskedLM, AutoTokenizer
from tqdm import tqdm
import random


@dataclass
class DetectionResult:
    """Result of anomaly detection"""
    is_malicious: bool
    confidence: float
    reconstruction_loss: float
    anomaly_score: float
    risk_level: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    details: Dict


class WAFDetector:
    """
    Anomaly-based detector using trained DeBERTa model
    
    DETECTION PHILOSOPHY (ZERO-DAY SAFE):
    - Model trained ONLY on benign traffic (never saw attacks!)
    - High reconstruction loss = Anomaly = Potential Attack
    - Can detect novel/zero-day attacks without signatures
    - Works on grammar/structure rather than patterns
    """
    
    def __init__(
        self,
        model_path: str,
        tokenizer_name: str = "microsoft/deberta-v3-small",
        max_length: int = 256,
        threshold_percentile: float = 98.0,
        device: Optional[str] = None,
        seed: Optional[int] = 42
    ):
        """
        Initialize detector
        
        Args:
            model_path: Path to trained model directory
            tokenizer_name: HuggingFace tokenizer identifier
            max_length: Maximum sequence length
            threshold_percentile: Percentile for anomaly threshold (98-99 recommended, higher = stricter)
            device: Device to use (None = auto-detect)
            seed: Random seed for reproducibility (None = random behavior)
        """
        self.max_length = max_length
        self.threshold_percentile = threshold_percentile
        self.seed = seed
        
        # Set random seeds for reproducibility
        if seed is not None:
            random.seed(seed)
            np.random.seed(seed)
            torch.manual_seed(seed)
            if torch.cuda.is_available():
                torch.cuda.manual_seed_all(seed)
        
        # Setup device
        if device is None:
            if torch.cuda.is_available():
                self.device = torch.device("cuda")
            elif torch.backends.mps.is_available():
                self.device = torch.device("mps")
            else:
                self.device = torch.device("cpu")
        else:
            self.device = torch.device(device)
        
        print(f"Loading detector on device: {self.device}")
        
        # Load tokenizer and model
        self.tokenizer = AutoTokenizer.from_pretrained(tokenizer_name)
        self.model = AutoModelForMaskedLM.from_pretrained(model_path)
        self.model.to(self.device)
        self.model.eval()
        
        # Thresholds (will be calibrated)
        self.anomaly_threshold = None
        self.baseline_stats = None
        
        print(f"✓ Model loaded from {model_path}")
    
    def _prepare_request_text(self, request: Dict) -> str:
        """
        Convert HTTP request to text format (same as training)
        
        Args:
            request: Request dictionary with method, path, headers, body, etc.
            
        Returns:
            Text representation of request
        """
        parts = []
        
        # Method and path
        method = request.get('method', 'GET').upper()
        path = request.get('path', '/')
        parts.append(f"METHOD:{method}")
        parts.append(f"PATH:{path}")
        
        # Query parameters
        if 'query' in request and request['query']:
            query_str = '&'.join([f"{k}={v}" for k, v in request['query'].items()])
            parts.append(f"QUERY:{query_str}")
        
        # Headers (selected important ones)
        headers = request.get('headers', {})
        important_headers = ['user-agent', 'content-type', 'accept', 'referer', 'cookie']
        for header in important_headers:
            if header in headers:
                parts.append(f"HEADER:{header}:{headers[header]}")
        
        # Body
        if 'body' in request and request['body']:
            body = request['body']
            if isinstance(body, dict):
                body = json.dumps(body)
            parts.append(f"BODY:{body}")
        
        return ' '.join(parts)
    
    def _compute_reconstruction_loss(
        self,
        text: str,
        mask_probability: float = 0.15,
        seed_offset: int = 0
    ) -> Tuple[float, Dict]:
        """
        Compute reconstruction loss by masking tokens and measuring prediction error
        
        Args:
            text: Input text
            mask_probability: Probability of masking each token
            seed_offset: Offset to add to seed for multiple samples (internal use)
            
        Returns:
            Tuple of (loss, details_dict)
        """
        # Set seed for this specific computation if seed is enabled
        if self.seed is not None:
            torch.manual_seed(self.seed + seed_offset)
        
        # Tokenize
        encoded = self.tokenizer(
            text,
            max_length=self.max_length,
            padding='max_length',
            truncation=True,
            return_tensors='pt'
        )
        
        input_ids = encoded['input_ids'].to(self.device)
        attention_mask = encoded['attention_mask'].to(self.device)
        
        # Create masked version
        labels = input_ids.clone()
        
        # Randomly mask tokens (excluding special tokens)
        probability_matrix = torch.full(labels.shape, mask_probability)
        special_tokens_mask = [
            self.tokenizer.get_special_tokens_mask(val, already_has_special_tokens=True)
            for val in labels.tolist()
        ]
        probability_matrix.masked_fill_(
            torch.tensor(special_tokens_mask, dtype=torch.bool), value=0.0
        )
        
        masked_indices = torch.bernoulli(probability_matrix).bool()
        labels[~masked_indices] = -100  # Only compute loss on masked tokens
        
        # Replace masked tokens with [MASK]
        input_ids[masked_indices] = self.tokenizer.mask_token_id
        
        # Get predictions
        with torch.no_grad():
            outputs = self.model(
                input_ids=input_ids,
                attention_mask=attention_mask,
                labels=labels
            )
            # Handle case where no tokens are masked
            if outputs.loss is None or torch.isnan(outputs.loss) or torch.isinf(outputs.loss):
                loss = 0.0
            else:
                loss = outputs.loss.item()
        
        # Compute per-token loss for analysis
        logits = outputs.logits
        loss_fct = torch.nn.CrossEntropyLoss(reduction='none')
        per_token_loss = loss_fct(
            logits.view(-1, self.model.config.vocab_size),
            labels.view(-1)
        )
        
        valid_losses = per_token_loss[per_token_loss != 0]  # Exclude unmasked tokens
        
        # Ensure no NaN/Inf values
        valid_losses = valid_losses[~torch.isnan(valid_losses) & ~torch.isinf(valid_losses)]
        
        details = {
            'mean_loss': loss,
            'max_token_loss': valid_losses.max().item() if len(valid_losses) > 0 else 0.0,
            'num_masked_tokens': int(masked_indices.sum().item()),
            'num_valid_tokens': int(attention_mask.sum().item())
        }
        
        return loss, details
    
    def calibrate(
        self,
        benign_requests: List[Dict],
        num_samples: Optional[int] = None
    ) -> Dict:
        """
        Calibrate detection threshold using benign requests
        
        Args:
            benign_requests: List of known benign requests
            num_samples: Number of samples to use for calibration (None = use all)
            
        Returns:
            Calibration statistics
        """
        # Use all samples if not specified
        if num_samples is None:
            num_samples = len(benign_requests)
        
        actual_samples = min(num_samples, len(benign_requests))
        print(f"\n🎯 Calibrating detector on {actual_samples} benign samples...")
        
        losses = []
        
        for idx, request in enumerate(tqdm(benign_requests[:actual_samples], desc="Calibration")):
            text = self._prepare_request_text(request)
            # Use index as seed offset for reproducible but varied calibration
            loss, _ = self._compute_reconstruction_loss(text, seed_offset=idx * 1000)
            losses.append(loss)
        
        losses = np.array(losses)
        
        # Filter out any NaN or Inf values
        losses = losses[~np.isnan(losses) & ~np.isinf(losses)]
        
        if len(losses) == 0:
            raise ValueError("All calibration losses are NaN/Inf! Check model and data.")
        
        # Compute statistics
        self.baseline_stats = {
            'mean': float(np.mean(losses)),
            'std': float(np.std(losses)),
            'median': float(np.median(losses)),
            'percentile_95': float(np.percentile(losses, 95)),
            'percentile_99': float(np.percentile(losses, 99)),
            'min': float(np.min(losses)),
            'max': float(np.max(losses))
        }
        
        # Set threshold at specified percentile
        self.anomaly_threshold = float(np.percentile(losses, self.threshold_percentile))
        
        print(f"\n📊 Calibration Complete:")
        print(f"   Mean Loss: {self.baseline_stats['mean']:.4f}")
        print(f"   Std Dev: {self.baseline_stats['std']:.4f}")
        print(f"   95th Percentile: {self.baseline_stats['percentile_95']:.4f}")
        print(f"   99th Percentile: {self.baseline_stats['percentile_99']:.4f}")
        print(f"   🚨 Anomaly Threshold ({self.threshold_percentile}th percentile): {self.anomaly_threshold:.4f}")
        
        return self.baseline_stats
    
    def detect(self, request: Dict, num_samples: int = 5) -> DetectionResult:
        """
        Detect if a request is malicious
        
        Args:
            request: Request dictionary
            num_samples: Number of masking samples to average over
            
        Returns:
            DetectionResult object
        """
        if self.anomaly_threshold is None:
            raise ValueError("Detector not calibrated! Call calibrate() first with benign samples.")
        
        # Convert request to text
        text = self._prepare_request_text(request)
        
        # Compute reconstruction loss multiple times and average
        losses = []
        all_details = []
        
        for i in range(num_samples):
            loss, details = self._compute_reconstruction_loss(text, seed_offset=i)
            losses.append(loss)
            all_details.append(details)
        
        avg_loss = np.mean(losses)
        std_loss = np.std(losses)
        max_loss = np.max(losses)
        
        # Compute anomaly score (normalized by baseline)
        z_score = (avg_loss - self.baseline_stats['mean']) / max(self.baseline_stats['std'], 1e-6)
        anomaly_score = max(0, z_score)  # Negative scores = normal
        
        # Determine if malicious
        is_malicious = avg_loss > self.anomaly_threshold
        
        # Compute confidence (normalized 0-100%)
        if is_malicious:
            # How many standard deviations above the mean
            confidence = min(99.9, z_score * 10)  # Scale z-score to percentage
        else:
            # Distance from threshold (inverted)
            distance_from_threshold = (self.anomaly_threshold - avg_loss) / self.anomaly_threshold
            confidence = min(99.9, distance_from_threshold * 100)
        
        # Determine risk level (only for malicious requests)
        if not is_malicious:
            risk_level = "LOW"
        elif avg_loss < self.anomaly_threshold * 1.2:
            risk_level = "LOW"
        elif avg_loss < self.anomaly_threshold * 1.5:
            risk_level = "MEDIUM"
        elif avg_loss < self.anomaly_threshold * 2.0:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"
        
        details = {
            'avg_loss': float(avg_loss),
            'std_loss': float(std_loss),
            'max_loss': float(max_loss),
            'z_score': float(z_score),
            'threshold': float(self.anomaly_threshold),
            'baseline_mean': float(self.baseline_stats['mean']),
            'baseline_std': float(self.baseline_stats['std']),
            'text_preview': text[:200] + '...' if len(text) > 200 else text,
            'num_samples': num_samples
        }
        
        return DetectionResult(
            is_malicious=bool(is_malicious),
            confidence=float(confidence),
            reconstruction_loss=float(avg_loss),
            anomaly_score=float(anomaly_score),
            risk_level=str(risk_level),
            details=details
        )
    
    def batch_detect(
        self,
        requests: List[Dict],
        show_progress: bool = True
    ) -> List[DetectionResult]:
        """
        Detect multiple requests in batch
        
        Args:
            requests: List of request dictionaries
            show_progress: Show progress bar
            
        Returns:
            List of DetectionResult objects
        """
        results = []
        
        iterator = tqdm(requests, desc="Detecting") if show_progress else requests
        
        for request in iterator:
            result = self.detect(request)
            results.append(result)
        
        return results
    
    def generate_report(
        self,
        results: List[DetectionResult],
        requests: List[Dict]
    ) -> Dict:
        """
        Generate detection report with statistics
        
        Args:
            results: List of DetectionResult objects
            requests: Original requests
            
        Returns:
            Report dictionary
        """
        total = len(results)
        malicious_count = sum(1 for r in results if r.is_malicious)
        benign_count = total - malicious_count
        
        # Risk level distribution
        risk_distribution = {
            'LOW': sum(1 for r in results if r.risk_level == 'LOW'),
            'MEDIUM': sum(1 for r in results if r.risk_level == 'MEDIUM'),
            'HIGH': sum(1 for r in results if r.risk_level == 'HIGH'),
            'CRITICAL': sum(1 for r in results if r.risk_level == 'CRITICAL')
        }
        
        # Average scores
        avg_loss = np.mean([r.reconstruction_loss for r in results])
        avg_confidence = np.mean([r.confidence for r in results])
        avg_anomaly_score = np.mean([r.anomaly_score for r in results])
        
        # Detection details
        malicious_indices = [i for i, r in enumerate(results) if r.is_malicious]
        
        report = {
            'summary': {
                'total_requests': total,
                'malicious_detected': malicious_count,
                'benign_detected': benign_count,
                'detection_rate': (malicious_count / total * 100) if total > 0 else 0,
                'avg_reconstruction_loss': float(avg_loss),
                'avg_confidence': float(avg_confidence),
                'avg_anomaly_score': float(avg_anomaly_score)
            },
            'risk_distribution': risk_distribution,
            'threshold': float(self.anomaly_threshold),
            'baseline_stats': self.baseline_stats,
            'malicious_indices': malicious_indices,
            'detailed_results': [
                {
                    'index': int(i),
                    'is_malicious': bool(r.is_malicious),
                    'confidence': float(r.confidence),
                    'reconstruction_loss': float(r.reconstruction_loss),
                    'anomaly_score': float(r.anomaly_score),
                    'risk_level': str(r.risk_level),
                    'request_preview': str(self._prepare_request_text(requests[i])[:100] + '...')
                }
                for i, r in enumerate(results)
            ]
        }
        
        return report
