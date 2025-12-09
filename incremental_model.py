"""
Incremental Model Training Module for WAF
Automatically trains the model when new benign logs accumulate
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
os.environ['WANDB_DISABLED'] = 'true'

import warnings
warnings.filterwarnings('ignore')

import json
import time
import threading
import torch
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
import numpy as np

from src.trainer import WAFTrainer, TrainingConfig
from src.tokenizer import RequestTokenizer


class IncrementalModelManager:
    """
    Manages incremental training of the WAF model
    
    INCREMENTAL TRAINING STRATEGY:
    - Collects new benign logs that pass classification
    - Triggers training when threshold is reached (default: 200 logs)
    - Fine-tunes existing model with new data (simple MLM continuation)
    - Updates model weights incrementally without catastrophic forgetting
    """
    
    def __init__(
        self,
        new_logs_file: str = "data/parsed/new_benign_logs.json",
        model_path: str = "models_30k/deberta-waf/best_model",
        output_dir: str = "models_30k/deberta-waf",
        trigger_count: int = 200,
        training_epochs: int = 2,
        auto_train: bool = True
    ):
        """
        Initialize incremental model manager
        
        Args:
            new_logs_file: Path to store new benign logs
            model_path: Path to current best model
            output_dir: Output directory for updated models
            trigger_count: Number of logs to trigger training
            training_epochs: Number of epochs for incremental training
            auto_train: Whether to automatically trigger training
        """
        self.new_logs_file = Path(new_logs_file)
        self.model_path = Path(model_path)
        self.output_dir = Path(output_dir)
        self.trigger_count = trigger_count
        self.training_epochs = training_epochs
        self.auto_train = auto_train
        
        # Create directories
        self.new_logs_file.parent.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize log file if it doesn't exist
        if not self.new_logs_file.exists():
            with open(self.new_logs_file, 'w') as f:
                json.dump([], f)
        
        # Training state
        self.is_training = False
        self.last_training_time = None
        self.total_trainings = 0
        self.training_lock = threading.Lock()
        
        # Statistics
        self.stats = {
            'total_logs_collected': 0,
            'total_trainings': 0,
            'last_training_time': None,
            'last_training_logs': 0,
            'training_history': []
        }
        
        self._load_stats()
        
        print(f"✅ Incremental Model Manager initialized")
        print(f"   - New logs file: {self.new_logs_file}")
        print(f"   - Model path: {self.model_path}")
        print(f"   - Trigger count: {self.trigger_count}")
        print(f"   - Training epochs: {self.training_epochs}")
        print(f"   - Auto-train: {self.auto_train}")
    
    def _load_stats(self):
        """Load statistics from file"""
        stats_file = self.output_dir / "incremental_stats.json"
        if stats_file.exists():
            try:
                with open(stats_file, 'r') as f:
                    self.stats = json.load(f)
            except Exception as e:
                print(f"⚠️  Failed to load stats: {e}")
    
    def _save_stats(self):
        """Save statistics to file"""
        stats_file = self.output_dir / "incremental_stats.json"
        try:
            with open(stats_file, 'w') as f:
                json.dump(self.stats, f, indent=2)
        except Exception as e:
            print(f"⚠️  Failed to save stats: {e}")
    
    def add_benign_log(self, request_dict: dict):
        """
        Add a new benign log entry
        
        Args:
            request_dict: Dictionary containing request information
        """
        try:
            # Add timestamp
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'request': request_dict
            }
            
            # Load existing logs
            with open(self.new_logs_file, 'r') as f:
                logs = json.load(f)
            
            # Append new log
            logs.append(log_entry)
            
            # Save back
            with open(self.new_logs_file, 'w') as f:
                json.dump(logs, f, indent=2)
            
            # Update stats
            self.stats['total_logs_collected'] = len(logs)
            self._save_stats()
            
            # Check if training should be triggered
            if self.auto_train and len(logs) >= self.trigger_count and not self.is_training:
                print(f"\n🔔 Trigger threshold reached: {len(logs)} logs collected")
                print(f"🚀 Starting incremental training...")
                
                # Start training in background thread
                training_thread = threading.Thread(
                    target=self._train_incremental,
                    daemon=True
                )
                training_thread.start()
            
            return len(logs)
            
        except Exception as e:
            print(f"❌ Failed to add benign log: {e}")
            return -1
    
    def get_log_count(self) -> int:
        """Get current count of new benign logs"""
        try:
            with open(self.new_logs_file, 'r') as f:
                logs = json.load(f)
            return len(logs)
        except Exception:
            return 0
    
    def get_stats(self) -> Dict:
        """Get current statistics"""
        current_count = self.get_log_count()
        return {
            **self.stats,
            'current_log_count': current_count,
            'is_training': self.is_training,
            'progress_to_trigger': f"{current_count}/{self.trigger_count}"
        }
    
    def _train_incremental(self):
        """
        Perform incremental training
        This method runs in a background thread
        """
        with self.training_lock:
            if self.is_training:
                print("⚠️  Training already in progress")
                return
            
            self.is_training = True
        
        try:
            print("\n" + "="*80)
            print("🎯 INCREMENTAL TRAINING STARTED")
            print("="*80)
            
            start_time = time.time()
            
            # Load new logs
            print("\n📖 Loading new benign logs...")
            with open(self.new_logs_file, 'r') as f:
                new_logs = json.load(f)
            
            num_logs = len(new_logs)
            print(f"   Found {num_logs} new benign logs")
            
            if num_logs < 10:
                print(f"⚠️  Too few logs for training (need at least 10)")
                return
            
            # Extract request data
            print("\n📝 Preparing training data...")
            requests = [log['request'] for log in new_logs]
            
            # Convert requests to text sequences
            def request_to_text_sequence(req_dict):
                """Convert request dict to text sequence"""
                parts = [
                    f"METHOD:{req_dict.get('method', 'GET')}",
                    f"PATH:{req_dict.get('path', '/')}",
                ]
                
                # Add query params
                query = req_dict.get('query', {})
                if query:
                    if isinstance(query, dict):
                        query_str = " ".join([f"{k}={v}" for k, v in query.items()])
                        parts.append(f"QUERY:{query_str}")
                    else:
                        parts.append(f"QUERY:{query}")
                
                # Add body if present
                body = req_dict.get('body')
                if body and body != "-" and body is not None:
                    parts.append(f"BODY:{body[:100]}")  # Limit body length
                
                # Add headers
                headers = req_dict.get('headers', {})
                if headers and isinstance(headers, dict):
                    content_type = headers.get('content-type') or headers.get('Content-Type')
                    if content_type:
                        parts.append(f"CONTENT_TYPE:{content_type}")
                
                return " ".join(parts)
            
            text_sequences = [request_to_text_sequence(req) for req in requests]
            
            # Tokenize new data
            print("\n🔤 Tokenizing new data...")
            tokenizer = RequestTokenizer(
                model_name="microsoft/deberta-v3-small",
                max_length=256
            )
            
            # Create temporary dataset
            temp_dir = self.output_dir / "temp_incremental"
            temp_dir.mkdir(exist_ok=True)
            
            train_path = temp_dir / "incremental_train.pt"
            val_path = temp_dir / "incremental_val.pt"
            
            # Split data (80/20)
            split_idx = int(len(text_sequences) * 0.8)
            train_sequences = text_sequences[:split_idx]
            val_sequences = text_sequences[split_idx:]
            
            print(f"   - Training samples: {len(train_sequences)}")
            print(f"   - Validation samples: {len(val_sequences)}")
            
            # Tokenize batches
            train_dataset = tokenizer.tokenize_batch(train_sequences)
            val_dataset = tokenizer.tokenize_batch(val_sequences)
            
            # Save tokenized datasets
            tokenizer.save_tokenized_dataset(train_dataset, str(train_path))
            tokenizer.save_tokenized_dataset(val_dataset, str(val_path))
            
            # Setup training configuration (reduced epochs for incremental)
            print(f"\n⚙️  Setting up training configuration...")
            config = TrainingConfig(
                model_name="microsoft/deberta-v3-small",
                max_length=256,
                batch_size=8,
                learning_rate=1e-5,  # Lower learning rate for fine-tuning
                num_epochs=self.training_epochs,
                warmup_steps=100,
                weight_decay=0.01,
                gradient_accumulation_steps=4,
                output_dir=str(self.output_dir),
                use_mps=True
            )
            
            # Initialize trainer
            print(f"\n🤖 Loading existing model from {self.model_path}...")
            trainer = WAFTrainer(config)
            
            # Load existing model for fine-tuning
            if self.model_path.exists():
                from transformers import AutoModelForMaskedLM
                trainer.model = AutoModelForMaskedLM.from_pretrained(str(self.model_path))
                trainer.model = trainer.model.to(trainer.device)
                print(f"   ✅ Loaded existing model")
            else:
                print(f"   ⚠️  Model not found, loading base model")
                trainer.load_model()
            
            # Train
            print(f"\n🏋️  Starting incremental training ({self.training_epochs} epochs)...")
            print(f"   Device: {trainer.device}")
            
            trainer.train(
                train_dataset_path=str(train_path),
                val_dataset_path=str(val_path),
                tokenizer=tokenizer
            )
            
            # Cleanup temporary files
            print(f"\n🧹 Cleaning up temporary files...")
            try:
                train_path.unlink()
                val_path.unlink()
                temp_dir.rmdir()
            except Exception as e:
                print(f"⚠️  Cleanup warning: {e}")
            
            # Archive trained logs
            print(f"\n📦 Archiving trained logs...")
            archive_file = self.output_dir / f"trained_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(archive_file, 'w') as f:
                json.dump(new_logs, f, indent=2)
            
            # Clear new logs file
            with open(self.new_logs_file, 'w') as f:
                json.dump([], f)
            
            # Update statistics
            training_time = time.time() - start_time
            self.total_trainings += 1
            self.last_training_time = datetime.now().isoformat()
            
            self.stats['total_trainings'] = self.total_trainings
            self.stats['last_training_time'] = self.last_training_time
            self.stats['last_training_logs'] = num_logs
            self.stats['training_history'].append({
                'timestamp': self.last_training_time,
                'logs_trained': num_logs,
                'epochs': self.training_epochs,
                'training_time_seconds': round(training_time, 2)
            })
            self._save_stats()
            
            print("\n" + "="*80)
            print("✅ INCREMENTAL TRAINING COMPLETED")
            print("="*80)
            print(f"   - Logs trained: {num_logs}")
            print(f"   - Training time: {training_time/60:.2f} minutes")
            print(f"   - Total trainings: {self.total_trainings}")
            print(f"   - Model saved: {self.output_dir}/best_model")
            print(f"   - Logs archived: {archive_file}")
            print("="*80 + "\n")
            
        except Exception as e:
            print(f"\n❌ Incremental training failed: {e}")
            import traceback
            traceback.print_exc()
        
        finally:
            self.is_training = False
    
    def trigger_training_manually(self) -> bool:
        """
        Manually trigger incremental training
        
        Returns:
            True if training started, False otherwise
        """
        if self.is_training:
            print("⚠️  Training already in progress")
            return False
        
        log_count = self.get_log_count()
        if log_count < 10:
            print(f"⚠️  Need at least 10 logs for training (current: {log_count})")
            return False
        
        print(f"🚀 Manually triggering incremental training with {log_count} logs...")
        
        # Start training in background thread
        training_thread = threading.Thread(
            target=self._train_incremental,
            daemon=True
        )
        training_thread.start()
        
        return True
    
    def update_trigger_count(self, new_count: int):
        """
        Update the trigger count
        
        Args:
            new_count: New trigger count threshold
        """
        if new_count < 10:
            print("⚠️  Trigger count must be at least 10")
            return False
        
        self.trigger_count = new_count
        print(f"✅ Trigger count updated to {new_count}")
        return True
    
    def clear_logs(self) -> int:
        """
        Clear all new benign logs (use with caution)
        
        Returns:
            Number of logs that were cleared
        """
        try:
            with open(self.new_logs_file, 'r') as f:
                logs = json.load(f)
            
            count = len(logs)
            
            # Backup before clearing
            backup_file = self.output_dir / f"logs_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(backup_file, 'w') as f:
                json.dump(logs, f, indent=2)
            
            # Clear
            with open(self.new_logs_file, 'w') as f:
                json.dump([], f)
            
            print(f"✅ Cleared {count} logs (backup: {backup_file})")
            return count
            
        except Exception as e:
            print(f"❌ Failed to clear logs: {e}")
            return 0


# Singleton instance
_incremental_manager = None


def get_incremental_manager(
    trigger_count: int = 200,
    training_epochs: int = 2,
    auto_train: bool = True
) -> IncrementalModelManager:
    """
    Get or create the singleton incremental manager
    
    Args:
        trigger_count: Number of logs to trigger training
        training_epochs: Number of epochs for training
        auto_train: Whether to auto-trigger training
        
    Returns:
        IncrementalModelManager instance
    """
    global _incremental_manager
    
    if _incremental_manager is None:
        _incremental_manager = IncrementalModelManager(
            trigger_count=trigger_count,
            training_epochs=training_epochs,
            auto_train=auto_train
        )
    
    return _incremental_manager


def main():
    """
    Test the incremental model manager
    """
    import argparse
    
    parser = argparse.ArgumentParser(description='Incremental Model Training Manager')
    parser.add_argument('--trigger-count', type=int, default=200, help='Number of logs to trigger training')
    parser.add_argument('--epochs', type=int, default=2, help='Number of training epochs')
    parser.add_argument('--test', action='store_true', help='Run in test mode with sample data')
    args = parser.parse_args()
    
    print("="*80)
    print("🔄 Incremental Model Training Manager")
    print("="*80)
    
    manager = get_incremental_manager(
        trigger_count=args.trigger_count,
        training_epochs=args.epochs,
        auto_train=True
    )
    
    if args.test:
        print("\n🧪 Running in test mode...")
        
        # Add some test logs
        print("\n📝 Adding test benign logs...")
        for i in range(5):
            test_request = {
                'method': 'GET',
                'path': f'/test/path/{i}',
                'query': {'param': f'value{i}'},
                'headers': {'User-Agent': 'TestClient'},
                'body': None
            }
            count = manager.add_benign_log(test_request)
            print(f"   Added log {i+1}, total: {count}")
        
        # Show stats
        print("\n📊 Current statistics:")
        stats = manager.get_stats()
        for key, value in stats.items():
            print(f"   {key}: {value}")
    
    else:
        print("\n✅ Manager initialized and ready")
        print(f"   Current log count: {manager.get_log_count()}")
        print(f"   Trigger threshold: {manager.trigger_count}")
        print(f"\nWaiting for logs to accumulate...")
        print("Press Ctrl+C to exit\n")
        
        try:
            while True:
                time.sleep(10)
                count = manager.get_log_count()
                print(f"Current logs: {count}/{manager.trigger_count}", end='\r')
        except KeyboardInterrupt:
            print("\n\n✅ Exiting...")


if __name__ == '__main__':
    main()
