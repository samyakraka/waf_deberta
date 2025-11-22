"""
Training Module for DeBERTa-based WAF Model
Optimized for Apple Silicon (M4 MacBook Air) with MPS acceleration
Uses Masked Language Modeling (MLM) for benign traffic pattern learning
Author: ISRO WAF Team
"""

# CRITICAL: Set environment variables BEFORE any imports to prevent mutex errors
import os
os.environ['TOKENIZERS_PARALLELISM'] = 'false'  # Prevent tokenizer mutex errors
os.environ['OMP_NUM_THREADS'] = '1'  # Limit OpenMP threads
os.environ['MKL_NUM_THREADS'] = '1'  # Limit MKL threads
os.environ['NUMEXPR_NUM_THREADS'] = '1'  # Limit NumExpr threads
os.environ['OPENBLAS_NUM_THREADS'] = '1'  # Limit OpenBLAS threads
os.environ['ABSL_MIN_LOG_LEVEL'] = '3'  # Suppress Abseil mutex warnings
os.environ['PYTORCH_ENABLE_MPS_FALLBACK'] = '1'

# Disable fork for multiprocessing (critical for macOS)
import multiprocessing
try:
    multiprocessing.set_start_method('spawn', force=True)
except RuntimeError:
    pass  # Already set

# Suppress warnings
import warnings
warnings.filterwarnings('ignore')

import json
import time
from typing import Dict, Optional, Tuple
from dataclasses import dataclass
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset, random_split
from transformers import (
    AutoModelForMaskedLM,
    AutoConfig,
    get_linear_schedule_with_warmup,
    DataCollatorForLanguageModeling
)
from tqdm import tqdm
import numpy as np


@dataclass
class TrainingConfig:
    """Configuration for training"""
    model_name: str = "microsoft/deberta-v3-small"
    max_length: int = 256
    batch_size: int = 8  # REDUCED: Prevents memory thrashing and system lag
    learning_rate: float = 2e-5
    num_epochs: int = 5
    warmup_steps: int = 500
    weight_decay: float = 0.01
    mlm_probability: float = 0.15  # Probability of masking tokens
    gradient_accumulation_steps: int = 4  # DOUBLED: Maintains effective batch size of 32
    max_grad_norm: float = 1.0
    save_steps: int = 1000
    eval_steps: int = 500
    logging_steps: int = 100
    output_dir: str = "models/deberta-waf"
    use_mps: bool = True  # Use Apple Silicon acceleration
    seed: int = 42


class WAFTrainer:
    """
    Trainer for DeBERTa-based WAF model
    
    TRAINING PHILOSOPHY (100% UNSUPERVISED - ZERO-DAY SAFE):
    - Trains ONLY on benign traffic (NEVER sees attacks!)
    - Uses Masked Language Modeling (MLM) to learn normal request grammar
    - At inference: High loss = Anomaly = Attack (even never-seen-before)
    - No signatures, no rules, no labeled attacks needed!
    
    Optimized for Apple Silicon with proper MPS handling
    """
    
    def __init__(self, config: TrainingConfig):
        """
        Initialize trainer
        
        Args:
            config: TrainingConfig object
        """
        self.config = config
        self.device = self._setup_device()
        
        # Set random seeds for reproducibility
        self._set_seed(config.seed)
        
        # Create output directory
        os.makedirs(config.output_dir, exist_ok=True)
        
        # Initialize model and tokenizer
        self.model = None
        self.tokenizer = None
        self.data_collator = None
        
        # Training state
        self.global_step = 0
        self.best_val_loss = float('inf')
        self.training_history = []
        
        print(f"Trainer initialized")
        print(f"Device: {self.device}")
        print(f"Output directory: {config.output_dir}")
    
    def _setup_device(self) -> torch.device:
        """
        Setup device with proper MPS handling for M4 MacBook Air
        
        Returns:
            torch.device object
        """
        # Set environment variables for better MPS stability
          # Prevent tokenizer mutex errors
        
        # Disable torch parallelism for MPS to prevent mutex issues
        torch.set_num_threads(1)
        torch.set_num_interop_threads(1)  # Reduces mutex deadlocks in OpenMP
        
        if self.config.use_mps and torch.backends.mps.is_available():
            device = torch.device("mps")
            print("✓ Using Apple Silicon MPS acceleration")
        elif torch.cuda.is_available():
            device = torch.device("cuda")
            print("✓ Using CUDA acceleration")
        else:
            device = torch.device("cpu")
            print("⚠ Using CPU (training will be slower)")
        
        return device
    
    def _set_seed(self, seed: int):
        """Set random seeds for reproducibility"""
        torch.manual_seed(seed)
        np.random.seed(seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(seed)
    
    def load_model(self, checkpoint_path: Optional[str] = None):
        """
        Load or initialize DeBERTa model
        
        Args:
            checkpoint_path: Path to checkpoint (optional)
        """
        if checkpoint_path and os.path.exists(checkpoint_path):
            print(f"Loading model from checkpoint: {checkpoint_path}")
            self.model = AutoModelForMaskedLM.from_pretrained(checkpoint_path)
        else:
            print(f"Initializing new model: {self.config.model_name}")
            config = AutoConfig.from_pretrained(self.config.model_name)
            self.model = AutoModelForMaskedLM.from_pretrained(
                self.config.model_name,
                config=config
            )
        
        # Move model to device with proper MPS handling
        self.model = self.model.to(self.device)
        
        # Force FP32 for MPS stability (prevents FP16 crashes on Apple Silicon)
        if self.device.type == "mps":
            self.model = self.model.to(torch.float32)
        
        # Enable gradient checkpointing for 50% less VRAM usage
        # Note: Disabled for MPS as it can cause backward pass issues
        if self.device.type != "mps":
            self.model.gradient_checkpointing_enable()
        else:
            print("⚠ Gradient checkpointing disabled for MPS compatibility")
        
        print(f"Model loaded successfully")
        print(f"Model parameters: {sum(p.numel() for p in self.model.parameters()):,}")
        print(f"Trainable parameters: {sum(p.numel() for p in self.model.parameters() if p.requires_grad):,}")
    
    def prepare_data_loaders(
        self,
        train_dataset_path: str,
        val_dataset_path: str
    ) -> Tuple[DataLoader, DataLoader]:
        """
        Prepare data loaders from tokenized datasets
        
        Args:
            train_dataset_path: Path to training dataset
            val_dataset_path: Path to validation dataset
            
        Returns:
            Tuple of (train_loader, val_loader)
        """
        print("Loading datasets...")
        
        # Load tokenized datasets
        train_data = torch.load(train_dataset_path)
        val_data = torch.load(val_dataset_path)
        
        # Create tensor datasets
        train_dataset = TensorDataset(
            train_data['input_ids'],
            train_data['attention_mask']
        )
        
        val_dataset = TensorDataset(
            val_data['input_ids'],
            val_data['attention_mask']
        )
        
        # Create data loaders with proper settings for MPS
        # num_workers=0 is CRITICAL for MPS to avoid mutex errors
        train_loader = DataLoader(
            train_dataset,
            batch_size=self.config.batch_size,
            shuffle=True,
            num_workers=0,  # MUST be 0 for MPS - prevents mutex/threading issues
            pin_memory=False,  # MPS doesn't support pinned memory
            persistent_workers=False  # No persistent workers needed
        )
        
        val_loader = DataLoader(
            val_dataset,
            batch_size=self.config.batch_size,
            shuffle=False,
            num_workers=0,  # MUST be 0 for MPS
            pin_memory=False,
            persistent_workers=False
        )
        
        print(f"Train batches: {len(train_loader)}")
        print(f"Validation batches: {len(val_loader)}")
        
        return train_loader, val_loader
    
    def _mask_tokens(
        self,
        input_ids: torch.Tensor,
        attention_mask: torch.Tensor
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Mask random tokens for MLM training (UNSUPERVISED)
        
        This is the CORE of unsupervised learning:
        - Randomly hide 15% of tokens: username=admin → username=[MASK]
        - Model learns to predict: [MASK] = "admin" from context
        - After training: Normal requests = low loss, Attacks = high loss!
        
        Args:
            input_ids: Input token IDs from BENIGN traffic
            attention_mask: Attention mask
            
        Returns:
            Tuple of (masked_input_ids, labels) where labels = original tokens
        """
        labels = input_ids.clone()  # Labels = ORIGINAL tokens (not attack/benign!)
        
        # Get the device from input tensors
        device = input_ids.device
        
        # Create probability matrix for masking on the correct device
        probability_matrix = torch.full(labels.shape, self.config.mlm_probability, device=device)
        
        # Don't mask special tokens (CLS, SEP, PAD) - use tokenizer method
        special_tokens_mask = [
            self.tokenizer.get_special_tokens_mask(val, already_has_special_tokens=True)
            for val in labels.tolist()
        ]
        special_tokens_mask = torch.tensor(special_tokens_mask, dtype=torch.bool, device=device)
        
        probability_matrix.masked_fill_(special_tokens_mask, value=0.0)
        probability_matrix.masked_fill_(attention_mask == 0, value=0.0)
        
        masked_indices = torch.bernoulli(probability_matrix).bool()
        labels[~masked_indices] = -100  # Only compute loss on masked tokens
        
        # Get mask token ID from tokenizer (not hard-coded)
        mask_token_id = self.tokenizer.mask_token_id
        
        # Correct MLM masking: 80% [MASK], 10% random, 10% keep original
        # 80% of the time, replace with [MASK]
        indices_replaced = masked_indices & (torch.rand(labels.shape, device=device) < 0.8)
        input_ids[indices_replaced] = mask_token_id
        
        # 10% of the time, replace with random token (of the remaining 20%)
        random_prob = torch.rand(labels.shape, device=device)
        indices_random = masked_indices & ~indices_replaced & (random_prob < 0.5)  # 0.5 of remaining 20% = 10% total
        random_words = torch.randint(len(self.tokenizer), labels.shape, dtype=torch.long, device=device)
        input_ids[indices_random] = random_words[indices_random]
        
        # Remaining 10% keep original token (automatically handled)
        
        return input_ids, labels
    
    def train_epoch(
        self,
        train_loader: DataLoader,
        optimizer: torch.optim.Optimizer,
        scheduler: torch.optim.lr_scheduler.LambdaLR,
        epoch: int
    ) -> Dict[str, float]:
        """
        Train for one epoch
        
        Args:
            train_loader: Training data loader
            optimizer: Optimizer
            scheduler: Learning rate scheduler
            epoch: Current epoch number
            
        Returns:
            Dictionary with training metrics
        """
        self.model.train()
        total_loss = 0
        total_batches = 0
        
        progress_bar = tqdm(train_loader, desc=f"Epoch {epoch}")
        
        for batch_idx, batch in enumerate(progress_bar):
            # Move batch to device
            input_ids = batch[0].to(self.device)
            attention_mask = batch[1].to(self.device)
            
            # Apply masking
            masked_input_ids, labels = self._mask_tokens(input_ids, attention_mask)
            
            # Forward pass with proper error handling for MPS
            try:
                outputs = self.model(
                    input_ids=masked_input_ids,
                    attention_mask=attention_mask,
                    labels=labels
                )
                loss = outputs.loss
                
                # Backward pass with gradient accumulation
                loss = loss / self.config.gradient_accumulation_steps
                loss.backward()
                
                # Update weights
                if (batch_idx + 1) % self.config.gradient_accumulation_steps == 0:
                    # Clip gradients
                    torch.nn.utils.clip_grad_norm_(
                        self.model.parameters(),
                        self.config.max_grad_norm
                    )
                    
                    optimizer.step()
                    scheduler.step()
                    optimizer.zero_grad()
                    
                    self.global_step += 1
                
                # Clear MPS cache periodically to prevent memory buildup
                if self.device.type == "mps" and batch_idx % 20 == 0:
                    torch.mps.empty_cache()
                
                # Track loss
                total_loss += loss.item() * self.config.gradient_accumulation_steps
                total_batches += 1
                
                # Update progress bar
                if batch_idx % self.config.logging_steps == 0:
                    avg_loss = total_loss / total_batches
                    progress_bar.set_postfix({
                        'loss': f'{avg_loss:.4f}',
                        'lr': f'{scheduler.get_last_lr()[0]:.2e}'
                    })
                
            except RuntimeError as e:
                if "MPS" in str(e):
                    print(f"\n⚠ MPS error encountered, skipping batch: {e}")
                    optimizer.zero_grad()
                    continue
                else:
                    raise e
        
        avg_loss = total_loss / total_batches if total_batches > 0 else 0
        
        return {
            'train_loss': avg_loss,
            'learning_rate': scheduler.get_last_lr()[0]
        }
    
    def evaluate(
        self,
        val_loader: DataLoader
    ) -> Dict[str, float]:
        """
        Evaluate model on validation set
        
        Args:
            val_loader: Validation data loader
            
        Returns:
            Dictionary with validation metrics
        """
        self.model.eval()
        total_loss = 0
        total_batches = 0
        
        # Set deterministic seeds for reproducible validation metrics
        torch.manual_seed(42)
        np.random.seed(42)
        
        with torch.no_grad():
            for batch in tqdm(val_loader, desc="Evaluating"):
                # Move batch to device
                input_ids = batch[0].to(self.device)
                attention_mask = batch[1].to(self.device)
                
                # Apply masking
                masked_input_ids, labels = self._mask_tokens(input_ids, attention_mask)
                
                try:
                    outputs = self.model(
                        input_ids=masked_input_ids,
                        attention_mask=attention_mask,
                        labels=labels
                    )
                    
                    loss = outputs.loss
                    total_loss += loss.item()
                    total_batches += 1
                    
                except RuntimeError as e:
                    if "MPS" in str(e):
                        print(f"\n⚠ MPS error during evaluation, skipping batch")
                        continue
                    else:
                        raise e
        
        avg_loss = total_loss / total_batches if total_batches > 0 else 0
        perplexity = np.exp(avg_loss)
        
        return {
            'val_loss': avg_loss,
            'perplexity': perplexity
        }
    
    def train(
        self,
        train_dataset_path: str,
        val_dataset_path: str,
        tokenizer=None
    ):
        """
        Main training loop
        
        Args:
            train_dataset_path: Path to training dataset
            val_dataset_path: Path to validation dataset
            tokenizer: Tokenizer instance (optional, will load if needed)
        """
        # Import tokenizer here to avoid circular dependency
        if tokenizer is None:
            from tokenizer import RequestTokenizer
            tokenizer = RequestTokenizer(
                model_name=self.config.model_name,
                max_length=self.config.max_length
            )
        
        self.tokenizer = tokenizer.tokenizer if hasattr(tokenizer, 'tokenizer') else tokenizer
        
        # Load model if not already loaded
        if self.model is None:
            self.load_model()
        
        # Prepare data loaders
        train_loader, val_loader = self.prepare_data_loaders(
            train_dataset_path,
            val_dataset_path
        )
        
        # Setup optimizer and scheduler
        optimizer = torch.optim.AdamW(
            self.model.parameters(),
            lr=self.config.learning_rate,
            weight_decay=self.config.weight_decay
        )
        
        total_steps = len(train_loader) * self.config.num_epochs // self.config.gradient_accumulation_steps
        scheduler = get_linear_schedule_with_warmup(
            optimizer,
            num_warmup_steps=self.config.warmup_steps,
            num_training_steps=total_steps
        )
        
        print(f"\n{'='*60}")
        print("Starting Training")
        print(f"{'='*60}")
        print(f"Total epochs: {self.config.num_epochs}")
        print(f"Batch size: {self.config.batch_size}")
        print(f"Gradient accumulation steps: {self.config.gradient_accumulation_steps}")
        print(f"Total optimization steps: {total_steps}")
        print(f"{'='*60}\n")
        
        start_time = time.time()
        
        # Training loop
        for epoch in range(1, self.config.num_epochs + 1):
            epoch_start = time.time()
            
            # Train
            train_metrics = self.train_epoch(train_loader, optimizer, scheduler, epoch)
            
            # Evaluate
            val_metrics = self.evaluate(val_loader)
            
            epoch_time = time.time() - epoch_start
            
            # Log metrics
            metrics = {
                'epoch': epoch,
                'train_loss': train_metrics['train_loss'],
                'val_loss': val_metrics['val_loss'],
                'perplexity': val_metrics['perplexity'],
                'learning_rate': train_metrics['learning_rate'],
                'epoch_time': epoch_time
            }
            self.training_history.append(metrics)
            
            print(f"\n{'='*60}")
            print(f"Epoch {epoch}/{self.config.num_epochs} Summary")
            print(f"{'='*60}")
            print(f"Train Loss: {train_metrics['train_loss']:.4f}")
            print(f"Val Loss: {val_metrics['val_loss']:.4f}")
            print(f"Perplexity: {val_metrics['perplexity']:.2f}")
            print(f"Learning Rate: {train_metrics['learning_rate']:.2e}")
            print(f"Epoch Time: {epoch_time:.2f}s")
            print(f"{'='*60}\n")
            
            # Save best model
            if val_metrics['val_loss'] < self.best_val_loss:
                self.best_val_loss = val_metrics['val_loss']
                self.save_checkpoint(f"best_model")
                print(f"✓ Saved best model (val_loss: {val_metrics['val_loss']:.4f})")
            
            # Save periodic checkpoint
            if epoch % 2 == 0:
                self.save_checkpoint(f"epoch_{epoch}")
        
        total_time = time.time() - start_time
        
        print(f"\n{'='*60}")
        print("Training Complete!")
        print(f"{'='*60}")
        print(f"Total time: {total_time/60:.2f} minutes")
        print(f"Best validation loss: {self.best_val_loss:.4f}")
        print(f"{'='*60}\n")
        
        # Save training history
        self.save_training_history()
    
    def save_checkpoint(self, checkpoint_name: str):
        """
        Save model checkpoint
        
        Args:
            checkpoint_name: Name for the checkpoint
        """
        checkpoint_dir = os.path.join(self.config.output_dir, checkpoint_name)
        os.makedirs(checkpoint_dir, exist_ok=True)
        
        # Save model
        self.model.save_pretrained(checkpoint_dir)
        
        # Save training state
        state = {
            'global_step': self.global_step,
            'best_val_loss': self.best_val_loss,
            'config': self.config.__dict__
        }
        
        torch.save(state, os.path.join(checkpoint_dir, 'training_state.pt'))
    
    def save_training_history(self):
        """Save training history to JSON"""
        history_path = os.path.join(self.config.output_dir, 'training_history.json')
        with open(history_path, 'w') as f:
            json.dump(self.training_history, f, indent=2)
        print(f"Training history saved to {history_path}")


def main():
    """Run training with saved tokenized datasets"""
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python trainer.py <train_dataset.pt> <val_dataset.pt> [output_dir] [num_epochs]")
        print("\nExample: python trainer.py data/tokenized/waf_benign_train.pt data/tokenized/waf_benign_val.pt models/deberta-waf 5")
        sys.exit(1)
    
    train_path = sys.argv[1]
    val_path = sys.argv[2]
    output_dir = sys.argv[3] if len(sys.argv) > 3 else "models/deberta-waf"
    num_epochs = int(sys.argv[4]) if len(sys.argv) > 4 else 5
    
    # Check if files exist
    if not os.path.exists(train_path):
        print(f"Error: Training dataset not found: {train_path}")
        print("\nPlease run tokenizer.py first to create tokenized datasets.")
        sys.exit(1)
    
    if not os.path.exists(val_path):
        print(f"Error: Validation dataset not found: {val_path}")
        print("\nPlease run tokenizer.py first to create tokenized datasets.")
        sys.exit(1)
    
    # Setup configuration (uses TrainingConfig defaults: batch_size=8, gradient_accumulation_steps=4)
    config = TrainingConfig(
        num_epochs=num_epochs,
        output_dir=output_dir,
        learning_rate=2e-5,
        warmup_steps=500
    )
    
    print("="*60)
    print("WAF Training Pipeline")
    print("="*60)
    print(f"Train dataset: {train_path}")
    print(f"Val dataset: {val_path}")
    print(f"Output directory: {output_dir}")
    print(f"Number of epochs: {num_epochs}")
    print("="*60 + "\n")
    
    # Initialize trainer
    trainer = WAFTrainer(config)
    
    # Start training
    trainer.train(
        train_dataset_path=train_path,
        val_dataset_path=val_path,
        tokenizer=None  # Will be loaded automatically
    )
    
    print("\n" + "="*60)
    print("✓ Training Complete!")
    print("="*60)
    print(f"Best model saved to: {output_dir}/best_model")
    print(f"Training history: {output_dir}/training_history.json")
    print("="*60)


if __name__ == "__main__":
    main()
