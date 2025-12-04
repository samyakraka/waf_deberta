#!/usr/bin/env python3
"""Debug script to test rule-based detection"""

import re
import json
from static_rules import STATIC_RULES

# Global compiled rules (simulating the app)
compiled_rules = {}

# Initialize rules
print("="*60)
print("INITIALIZING RULES")
print("="*60)
for category, patterns in STATIC_RULES.items():
    if patterns:
        try:
            compiled_rules[category] = [re.compile(p, re.IGNORECASE) for p in patterns]
            print(f"✓ {category}: {len(patterns)} patterns compiled")
        except Exception as e:
            print(f"✗ {category}: ERROR - {e}")

print(f"\nTotal categories loaded: {len(compiled_rules)}")

# Test request
print("\n" + "="*60)
print("TESTING REQUEST")
print("="*60)

request_dict = {
    'method': 'GET',
    'path': '/api/auth',
    'query': {'user': "admin' OR '1'='1", 'pass': 'anything'},
    'headers': {'user-agent': 'curl/7.79.1'},
    'body': None,
}

# Simulate check_rule_based_threats
path = str(request_dict.get('path', '')).lower()
query = json.dumps(request_dict.get('query', {})).lower()
body = str(request_dict.get('body', '')).lower()

full_text = f"{path} {query} {body}"

print(f"Full text to scan: {full_text}\n")

matched_patterns = []

threat_labels = {
    'sqli_patterns': 'SQL Injection',
    'sql_patterns': 'SQL Injection',
    'xss_patterns': 'XSS',
    'path_traversal_patterns': 'Path Traversal',
    'cmd_injection_patterns': 'Command Injection',
    'auth_bypass_patterns': 'Auth Bypass',
}

# Check all rule categories
for category, patterns in compiled_rules.items():
    threat_label = threat_labels.get(category, category.replace('_', ' ').title())
    for patt in patterns:
        if patt.search(full_text):
            matched_patterns.append((threat_label, patt.pattern[:100]))
            print(f"✓ MATCHED {threat_label}: {patt.pattern[:80]}")
            break  # One match per category is enough

print("\n" + "="*60)
if matched_patterns:
    threat_types = list(set([m[0] for m in matched_patterns]))
    print(f"✅ MALICIOUS DETECTED!")
    print(f"Threats: {', '.join(threat_types)}")
    print(f"Total patterns matched: {len(matched_patterns)}")
else:
    print("⚠️  NO THREATS DETECTED - CLASSIFIED AS SAFE")
    print("THIS IS THE BUG!")
