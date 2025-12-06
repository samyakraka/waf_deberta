#!/usr/bin/env python3
"""
End-to-End Test: Signature Approval Workflow
Demonstrates the complete flow from attack detection to Redis update
"""

import json
import sys
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).parent))

from signature_manager import SignatureManager
from src.redis_rules import RedisRuleManager

print("=" * 80)
print("🧪 SIGNATURE APPROVAL WORKFLOW TEST")
print("=" * 80)

# Step 1: Load attack logs
print("\n📋 Step 1: Loading attack logs from data/parsed/new_attack_logs.json")
sig_manager = SignatureManager()
attack_count = sig_manager.get_attack_count()
print(f"   ✅ Loaded {attack_count} attack log(s)")

if attack_count == 0:
    print("\n⚠️  No attack logs found. Send a test attack first!")
    sys.exit(1)

# Step 2: Extract signatures
print("\n🔍 Step 2: Extracting signatures from attack logs")
signatures = sig_manager.extract_signatures()

print(f"   ✅ Extracted {len(signatures)} signature category/categories")
for category, patterns in signatures.items():
    print(f"      • {category}: {len(patterns)} pattern(s)")
    for pattern in patterns:
        print(f"        - {pattern}")

# Step 3: Get pending signatures (what admin sees in UI)
print("\n📊 Step 3: Getting pending signatures (UI view)")
pending = sig_manager.get_pending_signatures()
print(f"   Total Attacks: {pending['total_attacks']}")
print(f"   Signature Categories: {pending['signature_categories']}")
print(f"   Total Patterns: {pending['total_patterns']}")

# Step 4: Simulate admin approval (add to Redis)
print("\n✅ Step 4: Simulating admin approval - adding to Redis")
try:
    redis_manager = RedisRuleManager(host='localhost', port=6379, db=0)
    
    patterns_added = 0
    for category, patterns in signatures.items():
        for pattern in patterns:
            success = redis_manager.add_rule(category, pattern)
            if success:
                patterns_added += 1
                print(f"   ✅ Added to Redis [{category}]: {pattern}")
    
    print(f"\n   📊 Total patterns added to Redis: {patterns_added}")
    
    # Step 5: Backup to rules_backup.json
    print("\n💾 Step 5: Backing up rules to rules_backup.json")
    backup_success = redis_manager.export_rules_to_json("rules_backup.json")
    
    if backup_success:
        print("   ✅ Backup created successfully!")
    else:
        print("   ⚠️  Backup failed!")
    
    # Step 6: Verify the rules are in Redis
    print("\n🔍 Step 6: Verifying rules in Redis")
    for category in signatures.keys():
        redis_patterns = redis_manager.get_rules(category)
        print(f"   • {category}: {len(redis_patterns)} pattern(s) in Redis")
    
    # Step 7: Health check
    print("\n🏥 Step 7: Redis health check")
    health = redis_manager.health_check()
    print(f"   Status: {health['status'].upper()}")
    print(f"   Connected: {health['connected']}")
    print(f"   Total Rules: {health['total_rules']}")
    
    print("\n" + "=" * 80)
    print("✅ WORKFLOW TEST COMPLETED SUCCESSFULLY!")
    print("=" * 80)
    print("\n📝 Summary:")
    print(f"   • Attack logs processed: {attack_count}")
    print(f"   • Signatures extracted: {pending['total_patterns']}")
    print(f"   • Patterns added to Redis: {patterns_added}")
    print(f"   • Backup created: {'✅' if backup_success else '❌'}")
    print("\n🔐 The WAF is now protected against these attacks!")
    
except Exception as e:
    print(f"\n❌ Error: {e}")
    print("\n⚠️  Make sure Redis is running: redis-server")
    sys.exit(1)
