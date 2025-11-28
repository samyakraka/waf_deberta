"""
Redis-based Rule Management for WAF
Stores and retrieves rule-based detection patterns from Redis
Author: ISRO WAF Team
"""

import redis
import json
import logging
from typing import List, Dict, Tuple, Optional

logger = logging.getLogger(__name__)


class RedisRuleManager:
    """Manages WAF detection rules in Redis"""
    
    # Redis keys for different rule categories - Comprehensive Attack Patterns
    RULE_KEYS = {
        # Legacy keys (for backward compatibility)
        'suspicious_paths': 'waf:rules:suspicious_paths',
        'sql_patterns': 'waf:rules:sql_patterns',
        'cmd_patterns': 'waf:rules:cmd_patterns',
        'encoding_patterns': 'waf:rules:encoding_patterns',
        
        # Comprehensive attack patterns
        'sqli_patterns': 'waf:rules:sqli_patterns',
        'xss_patterns': 'waf:rules:xss_patterns',
        'path_traversal_patterns': 'waf:rules:path_traversal_patterns',
        'cmd_injection_patterns': 'waf:rules:cmd_injection_patterns',
        'ldap_injection_patterns': 'waf:rules:ldap_injection_patterns',
        'xxe_patterns': 'waf:rules:xxe_patterns',
        'ssrf_patterns': 'waf:rules:ssrf_patterns',
        'rfi_patterns': 'waf:rules:rfi_patterns',
        'lfi_patterns': 'waf:rules:lfi_patterns',
        'nosql_injection_patterns': 'waf:rules:nosql_injection_patterns',
        'crlf_injection_patterns': 'waf:rules:crlf_injection_patterns',
        'template_injection_patterns': 'waf:rules:template_injection_patterns',
        'deserialization_patterns': 'waf:rules:deserialization_patterns',
        'hpp_patterns': 'waf:rules:hpp_patterns',
        'sensitive_data_patterns': 'waf:rules:sensitive_data_patterns',
        'shellshock_patterns': 'waf:rules:shellshock_patterns',
        'webshell_patterns': 'waf:rules:webshell_patterns',
        'auth_bypass_patterns': 'waf:rules:auth_bypass_patterns',
        'blocked_user_agents': 'waf:rules:blocked_user_agents',
        'suspicious_extensions': 'waf:rules:suspicious_extensions',
    }
    
    def __init__(self, host: str = 'localhost', port: int = 6379, db: int = 0, 
                 password: Optional[str] = None, decode_responses: bool = True):
        """
        Initialize Redis connection
        
        Args:
            host: Redis host
            port: Redis port
            db: Redis database number
            password: Redis password (optional)
            decode_responses: Decode responses as strings
        """
        try:
            self.redis_client = redis.Redis(
                host=host,
                port=port,
                db=db,
                password=password,
                decode_responses=decode_responses,
                socket_connect_timeout=5,
                socket_timeout=5
            )
            # Test connection
            self.redis_client.ping()
            logger.info(f"✅ Connected to Redis at {host}:{port}")
        except redis.ConnectionError as e:
            logger.error(f"❌ Failed to connect to Redis: {e}")
            raise
    
    def initialize_rules(self, rules_dict: Dict[str, List[str]]) -> bool:
        """
        Initialize Redis with rule patterns
        
        Args:
            rules_dict: Dictionary mapping rule categories to pattern lists
                       Keys should match RULE_KEYS
        
        Returns:
            True if successful
        """
        try:
            pipe = self.redis_client.pipeline()
            
            for category, patterns in rules_dict.items():
                if category in self.RULE_KEYS:
                    redis_key = self.RULE_KEYS[category]
                    # Delete existing rules
                    pipe.delete(redis_key)
                    # Add new rules
                    if patterns:
                        pipe.sadd(redis_key, *patterns)
                    logger.info(f"✅ Initialized {len(patterns)} patterns for {category}")
            
            pipe.execute()
            logger.info("✅ All rules initialized successfully in Redis")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize rules: {e}")
            return False
    
    def get_rules(self, category: str) -> List[str]:
        """
        Get all rules for a specific category
        
        Args:
            category: Rule category (e.g., 'suspicious_paths', 'sql_patterns')
        
        Returns:
            List of pattern strings
        """
        try:
            if category not in self.RULE_KEYS:
                logger.warning(f"Unknown rule category: {category}")
                return []
            
            redis_key = self.RULE_KEYS[category]
            patterns = list(self.redis_client.smembers(redis_key))
            return patterns
            
        except Exception as e:
            logger.error(f"❌ Failed to get rules for {category}: {e}")
            return []
    
    def get_all_rules(self) -> Dict[str, List[str]]:
        """
        Get all rules from Redis
        
        Returns:
            Dictionary mapping categories to pattern lists
        """
        all_rules = {}
        for category in self.RULE_KEYS.keys():
            all_rules[category] = self.get_rules(category)
        return all_rules
    
    def add_rule(self, category: str, pattern: str) -> bool:
        """
        Add a single rule pattern
        
        Args:
            category: Rule category
            pattern: Regex pattern to add
        
        Returns:
            True if successful
        """
        try:
            if category not in self.RULE_KEYS:
                logger.warning(f"Unknown rule category: {category}")
                return False
            
            redis_key = self.RULE_KEYS[category]
            self.redis_client.sadd(redis_key, pattern)
            logger.info(f"✅ Added pattern to {category}: {pattern}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to add rule: {e}")
            return False
    
    def remove_rule(self, category: str, pattern: str) -> bool:
        """
        Remove a single rule pattern
        
        Args:
            category: Rule category
            pattern: Regex pattern to remove
        
        Returns:
            True if successful
        """
        try:
            if category not in self.RULE_KEYS:
                logger.warning(f"Unknown rule category: {category}")
                return False
            
            redis_key = self.RULE_KEYS[category]
            result = self.redis_client.srem(redis_key, pattern)
            
            if result > 0:
                logger.info(f"✅ Removed pattern from {category}: {pattern}")
                return True
            else:
                logger.warning(f"Pattern not found in {category}: {pattern}")
                return False
            
        except Exception as e:
            logger.error(f"❌ Failed to remove rule: {e}")
            return False
    
    def get_rule_count(self, category: str) -> int:
        """
        Get count of rules in a category
        
        Args:
            category: Rule category
        
        Returns:
            Number of patterns
        """
        try:
            if category not in self.RULE_KEYS:
                return 0
            
            redis_key = self.RULE_KEYS[category]
            return self.redis_client.scard(redis_key)
            
        except Exception as e:
            logger.error(f"❌ Failed to get rule count: {e}")
            return 0
    
    def get_all_rule_counts(self) -> Dict[str, int]:
        """
        Get counts for all rule categories
        
        Returns:
            Dictionary mapping categories to counts
        """
        counts = {}
        for category in self.RULE_KEYS.keys():
            counts[category] = self.get_rule_count(category)
        return counts
    
    def clear_all_rules(self) -> bool:
        """
        Clear all rules from Redis (use with caution!)
        
        Returns:
            True if successful
        """
        try:
            pipe = self.redis_client.pipeline()
            for redis_key in self.RULE_KEYS.values():
                pipe.delete(redis_key)
            pipe.execute()
            logger.warning("⚠️  All rules cleared from Redis")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to clear rules: {e}")
            return False
    
    def export_rules_to_json(self, filepath: str) -> bool:
        """
        Export all rules to a JSON file
        
        Args:
            filepath: Path to save JSON file
        
        Returns:
            True if successful
        """
        try:
            all_rules = self.get_all_rules()
            with open(filepath, 'w') as f:
                json.dump(all_rules, f, indent=2)
            logger.info(f"✅ Rules exported to {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to export rules: {e}")
            return False
    
    def import_rules_from_json(self, filepath: str) -> bool:
        """
        Import rules from a JSON file
        
        Args:
            filepath: Path to JSON file
        
        Returns:
            True if successful
        """
        try:
            with open(filepath, 'r') as f:
                rules_dict = json.load(f)
            return self.initialize_rules(rules_dict)
            
        except Exception as e:
            logger.error(f"❌ Failed to import rules: {e}")
            return False
    
    def health_check(self) -> Dict[str, any]:
        """
        Check Redis connection and rule status
        
        Returns:
            Dictionary with health status
        """
        try:
            self.redis_client.ping()
            rule_counts = self.get_all_rule_counts()
            total_rules = sum(rule_counts.values())
            
            return {
                'status': 'healthy',
                'connected': True,
                'total_rules': total_rules,
                'rule_counts': rule_counts
            }
            
        except Exception as e:
            return {
                'status': 'unhealthy',
                'connected': False,
                'error': str(e)
            }
