#!/usr/bin/env python3
"""
Test Script for Incremental Training System
Verifies the incremental model manager works correctly
"""

import os
os.environ['TOKENIZERS_PARALLELISM'] = 'false'
os.environ['WANDB_DISABLED'] = 'true'

import sys
import json
from pathlib import Path

# Add project to path
sys.path.append(str(Path(__file__).parent))

from incremental_model import get_incremental_manager


def test_incremental_manager():
    """Test the incremental manager functionality"""
    print("="*80)
    print("🧪 Testing Incremental Training System")
    print("="*80)
    
    # Initialize manager with low threshold for testing
    print("\n1️⃣ Initializing manager...")
    manager = get_incremental_manager(
        trigger_count=10,  # Low threshold for testing
        training_epochs=1,  # Quick training
        auto_train=False   # Manual trigger for testing
    )
    
    # Check initial state
    print("\n2️⃣ Checking initial state...")
    stats = manager.get_stats()
    print(f"   Current logs: {stats['current_log_count']}")
    print(f"   Trigger threshold: {manager.trigger_count}")
    print(f"   Auto-train: {manager.auto_train}")
    
    # Add test benign logs
    print("\n3️⃣ Adding test benign logs...")
    test_logs = [
        {
            'method': 'GET',
            'path': '/api/users',
            'query': {'page': '1'},
            'headers': {'User-Agent': 'TestClient/1.0'},
            'body': None
        },
        {
            'method': 'POST',
            'path': '/api/login',
            'query': {},
            'headers': {'Content-Type': 'application/json'},
            'body': '{"username": "test", "password": "test123"}'
        },
        {
            'method': 'GET',
            'path': '/api/products',
            'query': {'category': 'electronics', 'limit': '10'},
            'headers': {'User-Agent': 'Mozilla/5.0'},
            'body': None
        },
        {
            'method': 'PUT',
            'path': '/api/users/123',
            'query': {},
            'headers': {'Content-Type': 'application/json'},
            'body': '{"name": "John Doe", "email": "john@example.com"}'
        },
        {
            'method': 'GET',
            'path': '/api/orders',
            'query': {'status': 'completed', 'user_id': '456'},
            'headers': {'Authorization': 'Bearer token123'},
            'body': None
        }
    ]
    
    for i, log in enumerate(test_logs, 1):
        count = manager.add_benign_log(log)
        print(f"   Added log {i}: {log['method']} {log['path']} (total: {count})")
    
    # Check updated state
    print("\n4️⃣ Checking updated state...")
    stats = manager.get_stats()
    print(f"   Current logs: {stats['current_log_count']}")
    print(f"   Progress: {stats['progress_to_trigger']}")
    
    # Read and display the log file
    print("\n5️⃣ Verifying log file...")
    log_file = Path("data/parsed/new_benign_logs.json")
    if log_file.exists():
        with open(log_file, 'r') as f:
            logs = json.load(f)
        print(f"   ✅ Log file exists with {len(logs)} entries")
        print(f"   First log timestamp: {logs[0]['timestamp']}")
        print(f"   Last log timestamp: {logs[-1]['timestamp']}")
    else:
        print(f"   ❌ Log file not found at {log_file}")
    
    # Test configuration update
    print("\n6️⃣ Testing configuration update...")
    success = manager.update_trigger_count(15)
    if success:
        print(f"   ✅ Trigger count updated to {manager.trigger_count}")
    else:
        print(f"   ❌ Failed to update trigger count")
    
    # Test stats retrieval
    print("\n7️⃣ Testing stats retrieval...")
    stats = manager.get_stats()
    print(f"   Total logs collected: {stats['total_logs_collected']}")
    print(f"   Total trainings: {stats['total_trainings']}")
    print(f"   Current log count: {stats['current_log_count']}")
    print(f"   Is training: {stats['is_training']}")
    print(f"   Progress to trigger: {stats['progress_to_trigger']}")
    
    # Note: We won't trigger actual training in the test since it requires:
    # - Valid model files
    # - Sufficient system resources
    # - Time to complete
    
    print("\n" + "="*80)
    print("✅ Incremental Manager Test Complete!")
    print("="*80)
    print("\nNote: Actual training test skipped (requires model and resources)")
    print("To test training, use: python incremental_model.py --test")
    print("\nTo clean up test data:")
    print("  rm data/parsed/new_benign_logs.json")
    print("="*80)


def test_api_integration():
    """Test that the UI integration works"""
    print("\n\n" + "="*80)
    print("🧪 Testing WAF UI Integration")
    print("="*80)
    
    try:
        from waf_integrated_ui import incremental_manager
        
        if incremental_manager:
            print("   ✅ Incremental manager integrated in UI")
        else:
            print("   ℹ️  Incremental manager not initialized (UI not started)")
    except ImportError as e:
        print(f"   ⚠️  Cannot import UI: {e}")
    
    print("="*80)


if __name__ == '__main__':
    try:
        # Test incremental manager
        test_incremental_manager()
        
        # Test API integration
        test_api_integration()
        
        print("\n✅ All tests completed successfully!")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
