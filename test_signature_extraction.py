#!/usr/bin/env python3
"""
Test signature extraction with header patterns
"""

from signature_manager import SignatureManager
import json

# Initialize signature manager
sig_manager = SignatureManager()

# Load attack logs
print(f"📊 Loaded {sig_manager.get_attack_count()} attack logs")

# Extract signatures
print("\n🔍 Extracting signatures...")
signatures = sig_manager.extract_signatures()

print("\n" + "="*70)
print("EXTRACTED SIGNATURES")
print("="*70)

for category, patterns in signatures.items():
    if patterns:
        print(f"\n📦 Category: {category.upper()}")
        print(f"   Patterns: {len(patterns)}")
        for i, pattern in enumerate(patterns, 1):
            print(f"   {i}. {pattern}")

# Get pending signatures details
print("\n" + "="*70)
print("PENDING SIGNATURES SUMMARY")
print("="*70)
pending = sig_manager.get_pending_signatures()
print(json.dumps(pending, indent=2))

# Get stats
print("\n" + "="*70)
print("ATTACK LOG STATISTICS")
print("="*70)
stats = sig_manager.get_stats()
print(json.dumps(stats, indent=2))
