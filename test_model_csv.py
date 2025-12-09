"""
Test DeBERTa WAF Model on bf8852ef.csv Dataset
Calculate accuracy, precision, recall, and confusion matrix
"""

import pandas as pd
import torch
import numpy as np
from sklearn.metrics import (confusion_matrix, classification_report, accuracy_score, 
                            precision_score, recall_score, f1_score)
import matplotlib.pyplot as plt
import seaborn as sns
import sys
import os
import json
import ast

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

try:
    from detector import WAFDetector
    print("✓ Successfully imported WAFDetector")
except Exception as e:
    print(f"❌ Error importing WAFDetector: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

def load_bf8852ef_data(filepath):
    """Load bf8852ef.csv file"""
    print(f"Loading dataset from {filepath}...")
    df = pd.read_csv(filepath)
    print(f"✓ Loaded {len(df)} requests")
    
    # Map label: "anomalous" -> 1, "benign" -> 0
    df['label_numeric'] = df['label'].apply(lambda x: 1 if str(x).lower() == 'anomalous' else 0)
    
    return df

def safe_parse_json(json_str):
    """Safely parse JSON string"""
    if pd.isna(json_str) or json_str == '':
        return {}
    try:
        # Try to parse as JSON
        return json.loads(json_str)
    except:
        try:
            # Try to evaluate as Python literal
            return ast.literal_eval(json_str)
        except:
            return {}

def prepare_request_from_bf8852ef(row):
    """Convert bf8852ef row to request format expected by detector"""
    # Parse headers
    headers = safe_parse_json(row.get('headers', '{}'))
    
    # Extract path and query from URL
    url = str(row.get('url', ''))
    path = '/'
    query_dict = {}
    
    if url:
        # Split URL into path and query
        if '?' in url:
            path_part, query_part = url.split('?', 1)
            # Extract path from full URL
            if '://' in path_part:
                path = '/' + path_part.split('/', 3)[-1] if '/' in path_part.split('://', 1)[1] else '/'
            else:
                path = path_part
            
            # Parse query parameters
            for param in query_part.split('&'):
                if '=' in param:
                    k, v = param.split('=', 1)
                    query_dict[k] = v
        else:
            # No query string
            if '://' in url:
                path = '/' + url.split('/', 3)[-1] if '/' in url.split('://', 1)[1] else '/'
            else:
                path = url
    
    # Get body content
    body = str(row.get('body', '')) if pd.notna(row.get('body')) else ''
    
    request = {
        'method': str(row.get('method', 'GET')),
        'path': path,
        'query': query_dict,
        'body': body,
        'status': 200,
        'headers': headers if isinstance(headers, dict) else {}
    }
    return request

def plot_confusion_matrix(cm, labels=['Benign', 'Malicious'], save_path='bf8852ef_confusion_matrix.png'):
    """Plot and save confusion matrix"""
    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=labels, yticklabels=labels,
                cbar_kws={'label': 'Count'})
    plt.title('Confusion Matrix - bf8852ef Dataset', fontsize=16, fontweight='bold')
    plt.ylabel('True Label', fontsize=12)
    plt.xlabel('Predicted Label', fontsize=12)
    plt.tight_layout()
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    print(f"✓ Confusion matrix saved to {save_path}")
    plt.close()

def main():
    print("="*80)
    print("Testing DeBERTa WAF Model on bf8852ef.csv Dataset")
    print("="*80)
    
    # Load data
    df = load_bf8852ef_data('bf8852ef.csv')
    
    # Extract true labels
    true_labels = df['label_numeric'].values
    print(f"\nLabel distribution:")
    print(f"  Benign (0): {np.sum(true_labels == 0)}")
    print(f"  Malicious (1): {np.sum(true_labels == 1)}")
    
    # Show anomaly type distribution
    print(f"\nAnomaly type distribution:")
    anomaly_counts = df['anomaly_type'].value_counts()
    for anomaly_type, count in anomaly_counts.items():
        print(f"  {anomaly_type}: {count}")
    
    # Initialize detector
    model_path = "models_30k/deberta-waf/best_model"
    print(f"\n{'='*80}")
    print(f"Loading model from {model_path}...")
    print(f"{'='*80}")
    
    # Use optimal threshold from previous testing (P75 = 3.65)
    optimal_threshold = 3.65
    
    try:
        # Detect best available device (MPS for M4, CUDA for GPU, CPU as fallback)
        if torch.backends.mps.is_available():
            device = "mps"
        elif torch.cuda.is_available():
            device = "cuda"
        else:
            device = "cpu"
        
        detector = WAFDetector(
            model_path=model_path,
            device=device
        )
        detector.anomaly_threshold = optimal_threshold
        print(f"✓ Model loaded successfully on {detector.device}")
        print(f"✓ Using optimal threshold: {optimal_threshold}")
    except Exception as e:
        print(f"❌ Error loading model: {e}")
        import traceback
        traceback.print_exc()
        return
    
    # Prepare all requests
    print(f"\n{'='*80}")
    print("Preparing requests...")
    print(f"{'='*80}")
    requests = []
    for idx, row in df.iterrows():
        if idx % 100 == 0:
            print(f"Preparing {idx}/{len(df)}...")
        requests.append(prepare_request_from_bf8852ef(row))
    
    # Compute reconstruction losses for all samples
    print(f"\n{'='*80}")
    print("Computing reconstruction losses for all samples...")
    print(f"{'='*80}")
    
    all_losses = []
    for i, request in enumerate(requests):
        if i % 100 == 0:
            print(f"Processing {i}/{len(requests)}...")
        text = detector._prepare_request_text(request)
        loss, _ = detector._compute_reconstruction_loss(text)
        all_losses.append(loss)
    
    all_losses = np.array(all_losses)
    
    # Separate losses by true label
    benign_losses = all_losses[true_labels == 0]
    malicious_losses = all_losses[true_labels == 1]
    
    print(f"\n📊 Loss Statistics:")
    if len(benign_losses) > 0:
        print(f"  Benign:")
        print(f"    Mean: {np.mean(benign_losses):.4f}, Std: {np.std(benign_losses):.4f}")
        print(f"    Median: {np.median(benign_losses):.4f}")
    if len(malicious_losses) > 0:
        print(f"  Malicious:")
        print(f"    Mean: {np.mean(malicious_losses):.4f}, Std: {np.std(malicious_losses):.4f}")
        print(f"    Median: {np.median(malicious_losses):.4f}")
    
    # Make predictions using optimal threshold
    predictions = [1 if loss > optimal_threshold else 0 for loss in all_losses]
    
    # Calculate metrics
    print(f"\n{'='*80}")
    print("EVALUATION RESULTS")
    print(f"{'='*80}")
    print(f"\nUsing threshold: {optimal_threshold:.4f}")
    
    accuracy = accuracy_score(true_labels, predictions)
    precision = precision_score(true_labels, predictions, zero_division=0)
    recall = recall_score(true_labels, predictions, zero_division=0)
    f1 = f1_score(true_labels, predictions, zero_division=0)
    
    print(f"\n📊 Overall Metrics:")
    print(f"  Accuracy:  {accuracy*100:.2f}%")
    print(f"  Precision: {precision*100:.2f}%")
    print(f"  Recall:    {recall*100:.2f}%")
    print(f"  F1-Score:  {f1*100:.2f}%")
    
    # Confusion Matrix
    cm = confusion_matrix(true_labels, predictions)
    print(f"\n📈 Confusion Matrix:")
    print(f"                 Predicted")
    print(f"                 Benign  Malicious")
    print(f"Actual Benign    {cm[0][0]:6d}  {cm[0][1]:6d}")
    print(f"Actual Malicious {cm[1][0]:6d}  {cm[1][1]:6d}")
    
    # Calculate detailed metrics
    tn, fp, fn, tp = cm.ravel()
    
    fpr_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
    
    print(f"\n📊 Detailed Metrics:")
    print(f"  True Positives (TP):  {tp:6d} - Correctly detected malicious")
    print(f"  True Negatives (TN):  {tn:6d} - Correctly detected benign")
    print(f"  False Positives (FP): {fp:6d} - Benign flagged as malicious")
    print(f"  False Negatives (FN): {fn:6d} - Malicious missed")
    print(f"\n  False Positive Rate: {fpr_rate*100:.2f}%")
    
    # Classification Report
    print(f"\n📋 Classification Report:")
    print(classification_report(true_labels, predictions, 
                                target_names=['Benign', 'Malicious'],
                                digits=4))
    
    # Plot confusion matrix
    plot_confusion_matrix(cm, save_path='bf8852ef_confusion_matrix.png')
    
    # Plot loss distribution
    if len(benign_losses) > 0 and len(malicious_losses) > 0:
        plt.figure(figsize=(12, 6))
        plt.hist(benign_losses, bins=50, alpha=0.6, label='Benign', color='green', edgecolor='black')
        plt.hist(malicious_losses, bins=50, alpha=0.6, label='Malicious', color='red', edgecolor='black')
        plt.axvline(optimal_threshold, color='blue', linestyle='--', linewidth=2, 
                    label=f'Threshold: {optimal_threshold:.4f}')
        plt.xlabel('Reconstruction Loss', fontsize=12)
        plt.ylabel('Frequency', fontsize=12)
        plt.title('Loss Distribution: Benign vs Malicious (bf8852ef)', fontsize=14, fontweight='bold')
        plt.legend()
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig('bf8852ef_loss_distribution.png', dpi=300, bbox_inches='tight')
        print(f"✓ Loss distribution saved to bf8852ef_loss_distribution.png")
        plt.close()
    
    # Save results
    output_file = 'bf8852ef_test_results.json'
    results = {
        'dataset': 'bf8852ef.csv',
        'total_samples': len(df),
        'threshold': float(optimal_threshold),
        'metrics': {
            'accuracy': float(accuracy),
            'precision': float(precision),
            'recall': float(recall),
            'f1_score': float(f1),
            'false_positive_rate': float(fpr_rate)
        },
        'confusion_matrix': cm.tolist(),
        'label_distribution': {
            'benign': int(np.sum(true_labels == 0)),
            'malicious': int(np.sum(true_labels == 1))
        },
        'anomaly_type_distribution': anomaly_counts.to_dict()
    }
    
    if len(benign_losses) > 0:
        results['loss_statistics'] = {
            'benign': {
                'mean': float(np.mean(benign_losses)),
                'std': float(np.std(benign_losses)),
                'median': float(np.median(benign_losses)),
                'min': float(np.min(benign_losses)),
                'max': float(np.max(benign_losses))
            }
        }
    
    if len(malicious_losses) > 0:
        if 'loss_statistics' not in results:
            results['loss_statistics'] = {}
        results['loss_statistics']['malicious'] = {
            'mean': float(np.mean(malicious_losses)),
            'std': float(np.std(malicious_losses)),
            'median': float(np.median(malicious_losses)),
            'min': float(np.min(malicious_losses)),
            'max': float(np.max(malicious_losses))
        }
    
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n✓ Results saved to {output_file}")
    print(f"\n{'='*80}")
    print("Testing Complete!")
    print(f"{'='*80}")

if __name__ == "__main__":
    main()