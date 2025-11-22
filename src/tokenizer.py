"""
Tokenization Module for DeBERTa-based WAF
Converts normalized HTTP requests into token sequences for transformer model
Author: ISRO WAF Team
"""

import os
os.environ['TOKENIZERS_PARALLELISM'] = 'false'  # Disable tokenizer parallelism to avoid mutex errors
os.environ['OMP_NUM_THREADS'] = '1'
os.environ['MKL_NUM_THREADS'] = '1'
os.environ['ABSL_MIN_LOG_LEVEL'] = '3'  # Suppress Abseil mutex warnings

import json
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import torch
from transformers import AutoTokenizer
from tqdm import tqdm
import pickle


@dataclass
class TokenizedDataset:
    """Container for tokenized dataset"""
    input_ids: torch.Tensor
    attention_mask: torch.Tensor
    labels: torch.Tensor
    metadata: Dict[str, Any]


class RequestTokenizer:
    """
    Tokenizer for HTTP requests using DeBERTa tokenizer
    Converts parsed requests into token sequences suitable for transformer models
    """
    
    def __init__(
        self,
        model_name: str = "microsoft/deberta-v3-small",
        max_length: int = 256,
        cache_dir: Optional[str] = None
    ):
        """
        Initialize tokenizer
        
        Args:
            model_name: HuggingFace model identifier
            max_length: Maximum sequence length
            cache_dir: Directory to cache tokenizer
        """
        print(f"Loading tokenizer: {model_name}")
        
        # Disable tokenizer parallelism to prevent mutex errors
        os.environ['TOKENIZERS_PARALLELISM'] = 'false'
        
        # Use slow tokenizer to avoid mutex issues on macOS
        self.tokenizer = AutoTokenizer.from_pretrained(
            model_name,
            cache_dir=cache_dir,
            use_fast=False  # CRITICAL: Use slow tokenizer to prevent mutex errors
        )
        self.max_length = max_length
        self.model_name = model_name
        
        # No additional special tokens needed for unsupervised MLM
        # Model learns from normal traffic patterns only
        
        print(f"Tokenizer loaded. Vocab size: {len(self.tokenizer)}")
        print(f"Max length: {max_length}")
    
    def tokenize_request(
        self,
        text_sequence: str,
        add_special_tokens: bool = True,
        return_tensors: str = "pt"
    ) -> Dict[str, torch.Tensor]:
        """
        Tokenize a single request text sequence
        
        Args:
            text_sequence: Text representation of HTTP request
            add_special_tokens: Whether to add [CLS] and [SEP] tokens
            return_tensors: Format of returned tensors
            
        Returns:
            Dictionary with input_ids, attention_mask, and token_type_ids
        """
        encoded = self.tokenizer(
            text_sequence,
            add_special_tokens=add_special_tokens,
            max_length=self.max_length,
            padding='max_length',
            truncation=True,
            return_tensors=return_tensors,
            return_attention_mask=True
        )
        
        return encoded
    
    def tokenize_batch(
        self,
        text_sequences: List[str],
        labels: Optional[List[int]] = None,
        batch_size: int = 32
    ) -> TokenizedDataset:
        """
        Tokenize a batch of requests (UNSUPERVISED - benign traffic only)
        
        Args:
            text_sequences: List of text representations
            labels: Placeholder tensor (unused in MLM - all set to 0 for compatibility)
            batch_size: Batch size for processing
            
        Returns:
            TokenizedDataset object
        """
        all_input_ids = []
        all_attention_masks = []
        
        print(f"Tokenizing {len(text_sequences)} sequences...")
        
        # Process in batches to avoid memory issues
        for i in tqdm(range(0, len(text_sequences), batch_size)):
            batch = text_sequences[i:i + batch_size]
            
            encoded = self.tokenizer(
                batch,
                add_special_tokens=True,
                max_length=self.max_length,
                padding='max_length',
                truncation=True,
                return_tensors='pt',
                return_attention_mask=True
            )
            
            all_input_ids.append(encoded['input_ids'])
            all_attention_masks.append(encoded['attention_mask'])
        
        # Concatenate all batches
        input_ids = torch.cat(all_input_ids, dim=0)
        attention_mask = torch.cat(all_attention_masks, dim=0)
        
        # Create placeholder labels tensor (required for DataLoader structure)
        # NOTE: These are NOT used in MLM training! MLM creates its own labels
        # from masked tokens. This is purely for dataset compatibility.
        # All requests are BENIGN - we train unsupervised on normal traffic only!
        if labels is None:
            labels = torch.zeros(len(text_sequences), dtype=torch.long)
        else:
            labels = torch.tensor(labels, dtype=torch.long)
        
        metadata = {
            'num_sequences': len(text_sequences),
            'max_length': self.max_length,
            'tokenizer': self.model_name,
            'vocab_size': len(self.tokenizer)
        }
        
        return TokenizedDataset(
            input_ids=input_ids,
            attention_mask=attention_mask,
            labels=labels,
            metadata=metadata
        )
    
    def save_tokenized_dataset(
        self,
        dataset: TokenizedDataset,
        output_path: str
    ):
        """
        Save tokenized dataset to disk
        
        Args:
            dataset: TokenizedDataset object
            output_path: Path to save file
        """
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        save_data = {
            'input_ids': dataset.input_ids,
            'attention_mask': dataset.attention_mask,
            'labels': dataset.labels,
            'metadata': dataset.metadata
        }
        
        torch.save(save_data, output_path)
        print(f"Tokenized dataset saved to {output_path}")
        print(f"Dataset size: {dataset.input_ids.shape}")
    
    def load_tokenized_dataset(
        self,
        input_path: str
    ) -> TokenizedDataset:
        """
        Load tokenized dataset from disk
        
        Args:
            input_path: Path to saved dataset
            
        Returns:
            TokenizedDataset object
        """
        data = torch.load(input_path)
        
        return TokenizedDataset(
            input_ids=data['input_ids'],
            attention_mask=data['attention_mask'],
            labels=data['labels'],
            metadata=data['metadata']
        )
    
    def decode_tokens(self, token_ids: torch.Tensor) -> str:
        """
        Decode token IDs back to text
        
        Args:
            token_ids: Tensor of token IDs
            
        Returns:
            Decoded text string
        """
        return self.tokenizer.decode(token_ids, skip_special_tokens=True)
    
    def get_token_statistics(self, text_sequences: List[str]) -> Dict[str, Any]:
        """
        Get statistics about tokenization
        
        Args:
            text_sequences: List of text sequences
            
        Returns:
            Dictionary with statistics
        """
        token_lengths = []
        
        for text in text_sequences[:1000]:  # Sample first 1000
            tokens = self.tokenizer.encode(text, add_special_tokens=True)
            token_lengths.append(len(tokens))
        
        return {
            'mean_length': sum(token_lengths) / len(token_lengths),
            'max_length': max(token_lengths),
            'min_length': min(token_lengths),
            'truncated_count': sum(1 for l in token_lengths if l > self.max_length)
        }


class DatasetBuilder:
    """
    Build training datasets from parsed logs
    Combines parser output with tokenizer
    """
    
    def __init__(
        self,
        tokenizer: RequestTokenizer,
        output_dir: str = "data/processed"
    ):
        """
        Initialize dataset builder
        
        Args:
            tokenizer: RequestTokenizer instance
            output_dir: Directory for output files
        """
        self.tokenizer = tokenizer
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def build_from_parsed_requests(
        self,
        parsed_requests: List[Any],
        dataset_name: str,
        train_split: float = 0.8
    ) -> tuple:
        """
        Build train/validation datasets from parsed requests
        
        Args:
            parsed_requests: List of ParsedRequest objects
            dataset_name: Name for the dataset
            train_split: Fraction of data for training
            
        Returns:
            Tuple of (train_dataset, val_dataset)
        """
        print(f"\nBuilding dataset: {dataset_name}")
        print(f"Total requests: {len(parsed_requests)}")
        
        # Convert to text sequences
        text_sequences = [req.to_text_sequence() for req in parsed_requests]
        
        # Get statistics
        stats = self.tokenizer.get_token_statistics(text_sequences)
        print(f"\nTokenization Statistics:")
        for key, value in stats.items():
            print(f"  {key}: {value}")
        
        # Split into train/val
        split_idx = int(len(text_sequences) * train_split)
        train_sequences = text_sequences[:split_idx]
        val_sequences = text_sequences[split_idx:]
        
        print(f"\nTrain samples: {len(train_sequences)}")
        print(f"Validation samples: {len(val_sequences)}")
        
        # Tokenize
        train_dataset = self.tokenizer.tokenize_batch(train_sequences)
        val_dataset = self.tokenizer.tokenize_batch(val_sequences)
        
        # Save datasets
        train_path = os.path.join(self.output_dir, f"{dataset_name}_train.pt")
        val_path = os.path.join(self.output_dir, f"{dataset_name}_val.pt")
        
        self.tokenizer.save_tokenized_dataset(train_dataset, train_path)
        self.tokenizer.save_tokenized_dataset(val_dataset, val_path)
        
        # Save metadata
        metadata = {
            'dataset_name': dataset_name,
            'total_requests': len(parsed_requests),
            'train_samples': len(train_sequences),
            'val_samples': len(val_sequences),
            'tokenization_stats': stats,
            'train_path': train_path,
            'val_path': val_path
        }
        
        metadata_path = os.path.join(self.output_dir, f"{dataset_name}_metadata.json")
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        print(f"\nDataset metadata saved to {metadata_path}")
        
        return train_dataset, val_dataset


def main():
    """Test tokenization and create datasets from parsed logs"""
    import sys
    from parser import load_parsed_requests
    
    if len(sys.argv) < 2:
        print("Usage: python tokenizer.py <parsed_requests_json> [output_dir]")
        print("\nExample: python tokenizer.py data/parsed/parsed_requests.json data/tokenized")
        sys.exit(1)
    
    parsed_file = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "data/tokenized"
    
    # Load parsed requests
    print(f"Loading parsed requests from {parsed_file}...")
    parsed_requests = load_parsed_requests(parsed_file)
    
    # Initialize tokenizer
    tokenizer = RequestTokenizer(
        model_name="microsoft/deberta-v3-small",
        max_length=256
    )
    
    # Build datasets
    builder = DatasetBuilder(tokenizer, output_dir)
    train_dataset, val_dataset = builder.build_from_parsed_requests(
        parsed_requests,
        dataset_name="waf_benign",
        train_split=0.8
    )
    
    print("\n" + "="*60)
    print("✓ Tokenization Complete!")
    print("="*60)
    print(f"Train dataset: {output_dir}/waf_benign_train.pt")
    print(f"Val dataset: {output_dir}/waf_benign_val.pt")
    print(f"Metadata: {output_dir}/waf_benign_metadata.json")
    print("\nUse these files for training with trainer.py")
    print("="*60)


if __name__ == "__main__":
    main()
