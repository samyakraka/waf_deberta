#!/usr/bin/env python3
"""
Redis Rule Management CLI
Interactive tool to manage WAF detection rules in Redis
Author: ISRO WAF Team
"""

import sys
from pathlib import Path
import json

# Add src to path
sys.path.append(str(Path(__file__).parent))

from src.redis_rules import RedisRuleManager
from config import REDIS_CONFIG


def print_menu():
    """Display main menu"""
    print("\n" + "=" * 60)
    print("🛡️  WAF Redis Rule Manager")
    print("=" * 60)
    print("\n📋 Options:")
    print("  1. View all rules")
    print("  2. View rules by category")
    print("  3. Add new rule")
    print("  4. Remove rule")
    print("  5. Export rules to JSON")
    print("  6. Import rules from JSON")
    print("  7. Health check")
    print("  8. Clear all rules (⚠️  Dangerous!)")
    print("  0. Exit")
    print("=" * 60)


def view_all_rules(manager):
    """Display all rules"""
    all_rules = manager.get_all_rules()
    counts = manager.get_all_rule_counts()
    
    print("\n📊 All Detection Rules:")
    print("-" * 60)
    
    total = 0
    for category, patterns in all_rules.items():
        count = counts[category]
        total += count
        category_name = category.replace('_', ' ').title()
        print(f"\n{category_name} ({count} patterns):")
        
        if patterns:
            for i, pattern in enumerate(sorted(patterns), 1):
                print(f"  {i:2d}. {pattern}")
        else:
            print("  (no patterns)")
    
    print("\n" + "-" * 60)
    print(f"Total: {total} patterns")


def view_category_rules(manager):
    """Display rules for a specific category"""
    categories = list(manager.RULE_KEYS.keys())
    
    print("\n📂 Available Categories:")
    for i, cat in enumerate(categories, 1):
        count = manager.get_rule_count(cat)
        print(f"  {i}. {cat.replace('_', ' ').title()} ({count} patterns)")
    
    try:
        choice = int(input("\nSelect category (number): "))
        if 1 <= choice <= len(categories):
            category = categories[choice - 1]
            patterns = manager.get_rules(category)
            
            print(f"\n🎯 {category.replace('_', ' ').title()} ({len(patterns)} patterns):")
            print("-" * 60)
            
            if patterns:
                for i, pattern in enumerate(sorted(patterns), 1):
                    print(f"  {i:2d}. {pattern}")
            else:
                print("  (no patterns)")
        else:
            print("❌ Invalid choice")
    except ValueError:
        print("❌ Invalid input")


def add_rule(manager):
    """Add a new rule"""
    categories = list(manager.RULE_KEYS.keys())
    
    print("\n➕ Add New Rule")
    print("\n📂 Select Category:")
    for i, cat in enumerate(categories, 1):
        print(f"  {i}. {cat.replace('_', ' ').title()}")
    
    try:
        choice = int(input("\nCategory (number): "))
        if 1 <= choice <= len(categories):
            category = categories[choice - 1]
            pattern = input("Pattern (regex): ").strip()
            
            if pattern:
                if manager.add_rule(category, pattern):
                    print(f"✅ Rule added to {category}")
                else:
                    print("❌ Failed to add rule")
            else:
                print("❌ Pattern cannot be empty")
        else:
            print("❌ Invalid choice")
    except ValueError:
        print("❌ Invalid input")


def remove_rule(manager):
    """Remove a rule"""
    categories = list(manager.RULE_KEYS.keys())
    
    print("\n➖ Remove Rule")
    print("\n📂 Select Category:")
    for i, cat in enumerate(categories, 1):
        count = manager.get_rule_count(cat)
        print(f"  {i}. {cat.replace('_', ' ').title()} ({count} patterns)")
    
    try:
        choice = int(input("\nCategory (number): "))
        if 1 <= choice <= len(categories):
            category = categories[choice - 1]
            patterns = manager.get_rules(category)
            
            if not patterns:
                print("❌ No patterns in this category")
                return
            
            print(f"\n🎯 {category.replace('_', ' ').title()} patterns:")
            for i, pattern in enumerate(sorted(patterns), 1):
                print(f"  {i:2d}. {pattern}")
            
            pattern_choice = int(input("\nPattern to remove (number): "))
            if 1 <= pattern_choice <= len(patterns):
                pattern = sorted(patterns)[pattern_choice - 1]
                confirm = input(f"\n⚠️  Remove '{pattern}'? (yes/no): ").lower()
                
                if confirm == 'yes':
                    if manager.remove_rule(category, pattern):
                        print(f"✅ Rule removed from {category}")
                    else:
                        print("❌ Failed to remove rule")
                else:
                    print("❌ Cancelled")
            else:
                print("❌ Invalid pattern number")
        else:
            print("❌ Invalid category")
    except ValueError:
        print("❌ Invalid input")


def export_rules(manager):
    """Export rules to JSON"""
    filename = input("\n💾 Export filename [rules_export.json]: ").strip()
    if not filename:
        filename = "rules_export.json"
    
    if manager.export_rules_to_json(filename):
        print(f"✅ Rules exported to {filename}")
    else:
        print("❌ Failed to export rules")


def import_rules(manager):
    """Import rules from JSON"""
    filename = input("\n📥 Import filename: ").strip()
    
    if not filename:
        print("❌ Filename required")
        return
    
    try:
        confirm = input(f"\n⚠️  This will replace all existing rules. Continue? (yes/no): ").lower()
        if confirm == 'yes':
            if manager.import_rules_from_json(filename):
                print(f"✅ Rules imported from {filename}")
            else:
                print("❌ Failed to import rules")
        else:
            print("❌ Cancelled")
    except Exception as e:
        print(f"❌ Error: {e}")


def health_check(manager):
    """Check Redis health"""
    health = manager.health_check()
    
    print("\n🏥 Health Check:")
    print("-" * 60)
    print(f"Status: {health['status'].upper()}")
    print(f"Connected: {'✅' if health['connected'] else '❌'}")
    
    if health['connected']:
        print(f"Total Rules: {health['total_rules']}")
        print("\nRule Counts:")
        for category, count in health['rule_counts'].items():
            print(f"  • {category.replace('_', ' ').title()}: {count}")
    else:
        print(f"Error: {health.get('error', 'Unknown')}")


def clear_all_rules(manager):
    """Clear all rules (dangerous!)"""
    print("\n⚠️  WARNING: This will delete ALL rules from Redis!")
    print("This action cannot be undone.")
    
    confirm1 = input("\nType 'DELETE ALL' to confirm: ").strip()
    if confirm1 == 'DELETE ALL':
        confirm2 = input("Are you absolutely sure? (yes/no): ").lower()
        if confirm2 == 'yes':
            if manager.clear_all_rules():
                print("✅ All rules cleared")
                print("💡 Run 'python init_redis_rules.py' to restore default rules")
            else:
                print("❌ Failed to clear rules")
        else:
            print("❌ Cancelled")
    else:
        print("❌ Cancelled")


def main():
    """Main CLI loop"""
    try:
        # Connect to Redis
        print("\n📡 Connecting to Redis...")
        manager = RedisRuleManager(
            host=REDIS_CONFIG['host'],
            port=REDIS_CONFIG['port'],
            db=REDIS_CONFIG['db'],
            password=REDIS_CONFIG['password'],
            decode_responses=REDIS_CONFIG['decode_responses']
        )
        print(f"✅ Connected to Redis at {REDIS_CONFIG['host']}:{REDIS_CONFIG['port']}")
        
    except Exception as e:
        print(f"❌ Failed to connect to Redis: {e}")
        print("\n💡 Make sure Redis is running:")
        print("   brew services start redis  # macOS")
        print("   sudo systemctl start redis  # Linux")
        return 1
    
    while True:
        print_menu()
        
        try:
            choice = input("\nSelect option: ").strip()
            
            if choice == '0':
                print("\n👋 Goodbye!")
                break
            elif choice == '1':
                view_all_rules(manager)
            elif choice == '2':
                view_category_rules(manager)
            elif choice == '3':
                add_rule(manager)
            elif choice == '4':
                remove_rule(manager)
            elif choice == '5':
                export_rules(manager)
            elif choice == '6':
                import_rules(manager)
            elif choice == '7':
                health_check(manager)
            elif choice == '8':
                clear_all_rules(manager)
            else:
                print("❌ Invalid option")
                
        except KeyboardInterrupt:
            print("\n\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"\n❌ Error: {e}")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
