"""
Initialize Redis with WAF Detection Rules
Populates Redis database with comprehensive rule-based patterns
Author: ISRO WAF Team
"""

import sys
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).parent))

from src.redis_rules import RedisRuleManager
from config import REDIS_CONFIG


# ============================================================================
# COMPREHENSIVE STATIC SECURITY RULES FOR WAF - ALL ATTACK PATTERNS
# ============================================================================

# ==================== SQL INJECTION PATTERNS ====================
SQLI_PATTERNS = [
    # Basic SQL injection
    r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
    r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
    r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
    r"((\%27)|(\'))union",
    r"exec(\s|\+)+(s|x)p\w+",
    
    # UNION-based injection
    r"UNION\s+SELECT",
    r"UNION\s+ALL\s+SELECT",
    r"UNION.*SELECT.*FROM",
    r"\+union\+",
    r"/\*.*\*/.*union",
    
    # Boolean-based blind injection
    r"SELECT.*FROM.*WHERE",
    r"' OR '1'='1",
    r"' OR 1=1--",
    r"admin'--",
    r"1=1|1=1--",
    r"' OR 'a'='a",
    r"' OR '1'='1'--",
    r"' OR 1=1#",
    r"OR 1=1",
    r"' OR '1'='1' /*",
    
    # Time-based blind injection
    r"SLEEP\s*\(",
    r"BENCHMARK\s*\(",
    r"WAITFOR\s+DELAY",
    r"pg_sleep\s*\(",
    r"dbms_lock\.sleep",
    
    # Error-based injection
    r"convert\s*\(.*,.*\)",
    r"cast\s*\(.*as.*\)",
    r"extractvalue\s*\(",
    r"updatexml\s*\(",
    
    # Stacked queries
    r";\s*DROP\s+",
    r";\s*DELETE\s+",
    r";\s*INSERT\s+",
    r";\s*UPDATE\s+",
    r";\s*CREATE\s+",
    r";\s*ALTER\s+",
    
    # Data manipulation
    r"INSERT\s+INTO",
    r"DELETE\s+FROM",
    r"DROP\s+(TABLE|DATABASE|SCHEMA|INDEX)",
    r"UPDATE.*SET",
    r"ALTER\s+TABLE",
    r"CREATE\s+TABLE",
    r"TRUNCATE\s+TABLE",
    r"GRANT\s+",
    r"REVOKE\s+",
    
    # Database enumeration
    r"information_schema",
    r"sys\.databases",
    r"sysobjects",
    r"syscolumns",
    r"TABLE_NAME",
    r"COLUMN_NAME",
    r"@@version",
    r"version\s*\(\)",
    r"database\s*\(\)",
    r"user\s*\(\)",
    r"current_user",
    
    # Advanced evasion
    r"concat\s*\(",
    r"chr\s*\(",
    r"char\s*\(",
    r"0x[0-9a-fA-F]+",
    r"\/\*\!.*\*\/",
    r"--\s",
    r"#.*",
    r"\/\*.*\*\/",
    
    # Hex encoding
    r"0x(27|3d|23|2d|2d)",
    
    # Stored procedures
    r"xp_cmdshell",
    r"sp_executesql",
    r"sp_makewebtask",
    r"xp_regread",
    r"xp_regwrite",
]

# ==================== XSS PATTERNS ====================
XSS_PATTERNS = [
    # Script tags
    r"<script[^>]*>.*?</script>",
    r"<script.*?>",
    r"</script>",
    r"<script\s*>",
    r"<script/",
    r"<SCRIPT",
    
    # Event handlers
    r"onerror\s*=",
    r"onload\s*=",
    r"onclick\s*=",
    r"onmouseover\s*=",
    r"onmouseout\s*=",
    r"onmousemove\s*=",
    r"onkeypress\s*=",
    r"onkeydown\s*=",
    r"onkeyup\s*=",
    r"onfocus\s*=",
    r"onblur\s*=",
    r"onchange\s*=",
    r"onsubmit\s*=",
    r"ondblclick\s*=",
    r"oncontextmenu\s*=",
    r"oninput\s*=",
    r"onpaste\s*=",
    r"onanimationstart\s*=",
    r"ontransitionend\s*=",
    
    # JavaScript execution
    r"javascript:",
    r"javascript\s*:",
    r"jAvAsCrIpT:",
    r"java\s*script:",
    
    # Dangerous tags
    r"<iframe",
    r"<object",
    r"<embed",
    r"<applet",
    r"<meta",
    r"<link",
    r"<style",
    r"<form",
    r"<input",
    r"<button",
    r"<textarea",
    r"<base",
    
    # Image-based XSS
    r"<img[^>]+src",
    r"<img.*onerror",
    r"<img.*onload",
    r"src\s*=\s*['\"]?javascript:",
    
    # SVG-based XSS
    r"<svg/onload=",
    r"<svg.*onload",
    r"<svg.*onerror",
    r"<svg>.*<script",
    
    # JavaScript functions
    r"eval\s*\(",
    r"alert\s*\(",
    r"confirm\s*\(",
    r"prompt\s*\(",
    r"setTimeout\s*\(",
    r"setInterval\s*\(",
    r"Function\s*\(",
    
    # DOM manipulation
    r"document\.cookie",
    r"document\.write",
    r"document\.writeln",
    r"window\.location",
    r"document\.location",
    r"document\.URL",
    r"document\.domain",
    r"window\.open",
    r"document\.body\.innerHTML",
    r"\.innerHTML\s*=",
    
    # Data exfiltration
    r"window\.location\.href",
    r"document\.referrer",
    r"localStorage",
    r"sessionStorage",
    
    # Expression/VBScript
    r"expression\s*\(",
    r"vbscript:",
    r"mocha:",
    r"livescript:",
    
    # Event attributes
    r"FSCommand",
    r"seekSegmentTime",
    
    # XML/HTML entities
    r"&#x",
    r"&#[0-9]+;",
    r"&lt;script",
    r"&lt;img",
    
    # Encoded attacks
    r"%3Cscript",
    r"%3C%2Fscript%3E",
    r"\u003c",
    r"\x3c",
    
    # Data protocol
    r"data:text/html",
    r"data:text/javascript",
]

# ==================== PATH TRAVERSAL PATTERNS ====================
PATH_TRAVERSAL_PATTERNS = [
    # Basic traversal
    r"\.\./",
    r"\.\.",
    r"\.\.\/",
    r"\.\.\\",
    
    # URL encoded
    r"%2e%2e",
    r"%2e%2e/",
    r"%2e%2e%2f",
    r"%252e%252e",
    r"..%2f",
    r"..%5c",
    
    # Double encoding
    r"%252e%252e%252f",
    r"%c0%ae%c0%ae",
    
    # Unix/Linux files
    r"/etc/passwd",
    r"/etc/shadow",
    r"/etc/hosts",
    r"/etc/group",
    r"/etc/issue",
    r"/etc/motd",
    r"/proc/self/environ",
    r"/proc/version",
    r"/proc/cmdline",
    r"/var/log/",
    r"/var/www/",
    r"/usr/local/",
    r"/home/",
    r"~/.ssh",
    r"~/.bash_history",
    
    # Windows files
    r"c:\\windows",
    r"c:\\winnt",
    r"boot\.ini",
    r"win\.ini",
    r"system\.ini",
    r"c:\\boot\.ini",
    r"\\windows\\system32",
    r"\\inetpub\\",
    
    # Null byte injection
    r"%00",
    r"\x00",
    
    # Absolute paths
    r"^/etc/",
    r"^/var/",
    r"^/usr/",
    r"^/proc/",
    r"^C:\\",
    r"^\\\\",
]

# ==================== COMMAND INJECTION PATTERNS ====================
CMD_INJECTION_PATTERNS = [
    # Command chaining
    r";\s*cat\s+",
    r";\s*ls\s+",
    r";\s*wget\s+",
    r";\s*curl\s+",
    r";\s*nc\s+",
    r";\s*netcat\s+",
    r";\s*telnet\s+",
    r";\s*ssh\s+",
    r";\s*ping\s+",
    
    # Pipe operations
    r"\|\s*cat\s+",
    r"\|\s*ls\s+",
    r"\|\s*grep\s+",
    r"\|\s*awk\s+",
    r"\|\s*sed\s+",
    r"\|\s*xargs\s+",
    
    # Command substitution
    r"`.*`",
    r"\$\(.*\)",
    r"\$\{.*\}",
    
    # Background operations
    r"&\s*(cat|ls|wget|curl)",
    r"&\s*nc\s+",
    r"&&\s*",
    r"\|\|\s*",
    
    # File operations
    r";\s*(rm|mv|cp|chmod|chown)\s+",
    r";\s*dd\s+",
    r";\s*tar\s+",
    r";\s*gzip\s+",
    
    # Network operations
    r";\s*nslookup\s+",
    r";\s*host\s+",
    r";\s*dig\s+",
    
    # System information
    r";\s*whoami",
    r";\s*id\s*",
    r";\s*uname",
    r";\s*hostname",
    r";\s*ifconfig",
    r";\s*ipconfig",
    
    # Process operations
    r";\s*ps\s+",
    r";\s*kill\s+",
    r";\s*killall\s+",
    
    # Scripting
    r";\s*python",
    r";\s*perl",
    r";\s*php",
    r";\s*ruby",
    r";\s*bash",
    r";\s*sh\s+",
    
    # Redirection
    r">\s*/dev/null",
    r"<\s*/etc/passwd",
    r"2>&1",
]

# ==================== LDAP INJECTION PATTERNS ====================
LDAP_INJECTION_PATTERNS = [
    r"\*\)\(\|",
    r"\*\)\(&",
    r"\)\(\|",
    r"\)\(&",
    r"\(\|",
    r"\(&",
    r"\)\(uid=\*\)",
    r"\)\(cn=\*\)",
    r"\*\|",
    r"\*&",
    r"admin\*",
    r"\(\|\(uid=\*\)",
]

# ==================== XXE PATTERNS ====================
XXE_PATTERNS = [
    r"<!ENTITY",
    r"<!DOCTYPE.*ENTITY",
    r"SYSTEM\s+[\"']file://",
    r"SYSTEM\s+[\"']http://",
    r"SYSTEM\s+[\"']https://",
    r"<!DOCTYPE.*\[",
    r"<!ELEMENT",
    r"SYSTEM\s+[\"']php://",
    r"SYSTEM\s+[\"']expect://",
    r"SYSTEM\s+[\"']data://",
]

# ==================== SSRF PATTERNS ====================
SSRF_PATTERNS = [
    r"localhost",
    r"127\.0\.0\.1",
    r"0\.0\.0\.0",
    r"169\.254\.169\.254",
    r"::1",
    r"0x7f000001",
    r"2130706433",
    r"0177\.0\.0\.1",
    r"0x7f\.0x0\.0x0\.0x1",
    r"localtest\.me",
    r"\.local",
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    r"172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}",
    r"192\.168\.\d{1,3}\.\d{1,3}",
    r"metadata\.google\.internal",
    r"169\.254\.169\.254/latest/meta-data",
]

# ==================== REMOTE FILE INCLUSION (RFI) ====================
RFI_PATTERNS = [
    r"http://.*\?",
    r"https://.*\?",
    r"ftp://.*\?",
    r"php://input",
    r"php://filter",
    r"expect://",
    r"data://",
    r"file://",
    r"glob://",
    r"phar://",
    r"zip://",
]

# ==================== LOCAL FILE INCLUSION (LFI) ====================
LFI_PATTERNS = [
    r"\.\.\/",
    r"\.\.\\",
    r"php://filter",
    r"/proc/self/environ",
    r"access\.log",
    r"error\.log",
    r"/var/log/apache",
    r"/var/log/nginx",
]

# ==================== NOSQL INJECTION ====================
NOSQL_INJECTION_PATTERNS = [
    r"\$ne",
    r"\$gt",
    r"\$lt",
    r"\$gte",
    r"\$lte",
    r"\$regex",
    r"\$where",
    r"\$eq",
    r"\$in",
    r"\$nin",
    r"\{\s*\$ne\s*:",
    r"\{\s*\$gt\s*:",
    r"\[\s*\$ne\s*\]",
    r"true.*\$ne",
    r"1.*\$ne",
]

# ==================== CRLF INJECTION ====================
CRLF_INJECTION_PATTERNS = [
    r"%0d%0a",
    r"%0D%0A",
    r"\r\n",
    r"\\r\\n",  # Escaped CRLF
    r"%0aSet-Cookie:",
    r"%0d%0aSet-Cookie:",
    r"\nSet-Cookie:",
    r"\r\nSet-Cookie:",
    r"\\nSet-Cookie:",  # Escaped
    r"%0aLocation:",
    r"%0d%0aLocation:",
    r"\\nLocation:",  # Escaped
    r"HTTP/1\.[01]\\r\\n",  # HTTP request smuggling
    r"HTTP/1\.[01]%0d%0a",  # URL-encoded HTTP smuggling
    r"\\n[xX]-[A-Za-z-]+:",  # Escaped header injection
    r"%0a[xX]-[A-Za-z-]+:",  # URL-encoded header injection
]

# ==================== TEMPLATE INJECTION ====================
TEMPLATE_INJECTION_PATTERNS = [
    r"\{\{.*\}\}",
    r"\{\%.*\%\}",
    r"\$\{.*\}",
    r"<%.*%>",
    r"#{.*}",
    r"@\(.*\)",
    r"7\*7",
    r"\{\{7\*7\}\}",
    r"\{\{config\}\}",
    r"\{\{request\}\}",
    r"__import__",
]

# ==================== DESERIALIZATION ATTACKS ====================
DESERIALIZATION_PATTERNS = [
    r"O:\d+:",
    r"a:\d+:\{",
    r"s:\d+:",
    r"rO0AB",
    r"H4sIAAAAAAAA",
    r"__reduce__",
    r"__setstate__",
    r"pickle\.loads",
    r"yaml\.load",
    r"json\.loads.*eval",
]

# ==================== HTTP PARAMETER POLLUTION ====================
HPP_PATTERNS = [
    r"&\w+=.*&\w+=",
    r"\?\w+=.*&\w+=.*&\w+=",
]

# ==================== SENSITIVE DATA PATTERNS ====================
SENSITIVE_DATA_PATTERNS = [
    r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b",  # Credit card
    r"\b\d{3}-\d{2}-\d{4}\b",  # SSN
    r"password\s*=\s*['\"]?[^\s'\"]+",
    r"api[_\-]?key\s*=\s*['\"]?[^\s'\"]+",
    r"access[_\-]?token\s*=\s*['\"]?[^\s'\"]+",
    r"secret\s*=\s*['\"]?[^\s'\"]+",
    r"BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY",
]

# ==================== SHELLSHOCK PATTERNS ====================
SHELLSHOCK_PATTERNS = [
    r"\(\)\s*\{",
    r"bash -c",
    r"\(\)\s*\{\s*:\s*;\s*\}",
]

# ==================== WEB SHELL PATTERNS ====================
WEBSHELL_PATTERNS = [
    r"c99shell",
    r"r57shell",
    r"b374k",
    r"wso\.php",
    r"FilesMan",
    r"shell_exec\s*\(",
    r"passthru\s*\(",
    r"system\s*\(",
    r"exec\s*\(",
    r"popen\s*\(",
    r"proc_open\s*\(",
    r"pcntl_exec\s*\(",
]

# ==================== AUTHENTICATION BYPASS ====================
AUTH_BYPASS_PATTERNS = [
    r"' OR '1'='1",
    r"' OR 1=1--",
    r"admin' OR '1'='1",
    r"admin'--",
    r"' OR 'a'='a",
    r"') OR ('1'='1",
    r"' OR '1'='1' /*",
    r"1' OR '1'='1",
]

# ==================== SUSPICIOUS USER AGENTS ====================
BLOCKED_USER_AGENTS = [
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "nessus",
    "burp",
    "dirbuster",
    "metasploit",
    "havij",
    "acunetix",
    "netsparker",
    "w3af",
    "ZAP",
    "AppScan",
    "WebInspect",
    "Paros",
    "Grendel",
    "Hydra",
    "John",
]

# ==================== SUSPICIOUS FILE EXTENSIONS ====================
SUSPICIOUS_EXTENSIONS = [
    ".bak",
    ".old",
    ".tmp",
    ".temp",
    ".swp",
    ".swo",
    ".config",
    ".conf",
    ".sql",
    ".log",
    ".env",
    ".git",
    ".svn",
    ".DS_Store",
    ".htaccess",
    ".htpasswd",
    ".ini",
    ".cfg",
    ".yaml",
    ".yml",
    ".json",
    ".xml",
    ".db",
    ".sqlite",
    ".mdb",
    ".dump",
    ".backup",
    "~",
]

# ==================== SEVERITY LEVELS ====================
SEVERITY_LEVELS = {
    "sqli_patterns": "CRITICAL",
    "xss_patterns": "HIGH",
    "path_traversal_patterns": "HIGH",
    "cmd_injection_patterns": "CRITICAL",
    "ldap_injection_patterns": "HIGH",
    "xxe_patterns": "HIGH",
    "ssrf_patterns": "HIGH",
    "rfi_patterns": "CRITICAL",
    "lfi_patterns": "HIGH",
    "nosql_injection_patterns": "HIGH",
    "crlf_injection_patterns": "MEDIUM",
    "template_injection_patterns": "CRITICAL",
    "deserialization_patterns": "CRITICAL",
    "hpp_patterns": "MEDIUM",
    "sensitive_data_patterns": "HIGH",
    "shellshock_patterns": "CRITICAL",
    "webshell_patterns": "CRITICAL",
    "auth_bypass_patterns": "CRITICAL",
    "blocked_user_agents": "MEDIUM",
    "suspicious_extensions": "MEDIUM",
}

# ==================== OWASP TOP 10 MAPPING ====================
OWASP_MAPPING = {
    "A01:2021-Broken Access Control": [
        "path_traversal_patterns",
        "lfi_patterns",
        "auth_bypass_patterns"
    ],
    "A02:2021-Cryptographic Failures": [
        "sensitive_data_patterns"
    ],
    "A03:2021-Injection": [
        "sqli_patterns",
        "nosql_injection_patterns",
        "cmd_injection_patterns",
        "ldap_injection_patterns",
        "template_injection_patterns",
        "crlf_injection_patterns"
    ],
    "A05:2021-Security Misconfiguration": [
        "blocked_user_agents",
        "suspicious_extensions"
    ],
    "A07:2021-Identification and Authentication Failures": [
        "auth_bypass_patterns"
    ],
    "A08:2021-Software and Data Integrity Failures": [
        "deserialization_patterns"
    ],
    "A10:2021-Server-Side Request Forgery": [
        "ssrf_patterns"
    ],
    "Cross-Site Scripting (XSS)": [
        "xss_patterns"
    ],
    "Remote File Inclusion": [
        "rfi_patterns"
    ],
    "XXE": [
        "xxe_patterns"
    ],
}



def get_rule_statistics():
    """Get comprehensive statistics about all rules."""
    rules_dict = get_all_rules()
    stats = {
        "total_categories": len(rules_dict),
        "total_rules": 0,
        "by_category": {},
        "by_severity": {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }
    }
    
    for key, value in rules_dict.items():
        if isinstance(value, list):
            count = len(value)
            stats["by_category"][key] = count
            stats["total_rules"] += count
            
            # Count by severity
            severity = SEVERITY_LEVELS.get(key, "LOW")
            if severity in stats["by_severity"]:
                stats["by_severity"][severity] += count
    
    return stats


def get_all_rules():
    """Returns all attack patterns in a dictionary."""
    return {
        'sqli_patterns': SQLI_PATTERNS,
        'xss_patterns': XSS_PATTERNS,
        'path_traversal_patterns': PATH_TRAVERSAL_PATTERNS,
        'cmd_injection_patterns': CMD_INJECTION_PATTERNS,
        'ldap_injection_patterns': LDAP_INJECTION_PATTERNS,
        'xxe_patterns': XXE_PATTERNS,
        'ssrf_patterns': SSRF_PATTERNS,
        'rfi_patterns': RFI_PATTERNS,
        'lfi_patterns': LFI_PATTERNS,
        'nosql_injection_patterns': NOSQL_INJECTION_PATTERNS,
        'crlf_injection_patterns': CRLF_INJECTION_PATTERNS,
        'template_injection_patterns': TEMPLATE_INJECTION_PATTERNS,
        'deserialization_patterns': DESERIALIZATION_PATTERNS,
        'hpp_patterns': HPP_PATTERNS,
        'sensitive_data_patterns': SENSITIVE_DATA_PATTERNS,
        'shellshock_patterns': SHELLSHOCK_PATTERNS,
        'webshell_patterns': WEBSHELL_PATTERNS,
        'auth_bypass_patterns': AUTH_BYPASS_PATTERNS,
        'blocked_user_agents': BLOCKED_USER_AGENTS,
        'suspicious_extensions': SUSPICIOUS_EXTENSIONS,
    }


def get_owasp_coverage():
    """Get OWASP Top 10 coverage statistics."""
    rules_dict = get_all_rules()
    coverage = {}
    for owasp_cat, rule_types in OWASP_MAPPING.items():
        total_rules = sum(len(rules_dict.get(rt, [])) for rt in rule_types if isinstance(rules_dict.get(rt), list))
        coverage[owasp_cat] = {
            "rule_categories": len(rule_types),
            "total_rules": total_rules,
            "categories": rule_types
        }
    return coverage


def main():
    """Initialize Redis with comprehensive WAF rules"""
    print("=" * 80)
    print("🛡️  Initializing Redis with COMPREHENSIVE WAF Detection Rules")
    print("=" * 80)
    
    # Connect to Redis
    print(f"\n📡 Connecting to Redis at {REDIS_CONFIG['host']}:{REDIS_CONFIG['port']}...")
    try:
        rule_manager = RedisRuleManager(
            host=REDIS_CONFIG['host'],
            port=REDIS_CONFIG['port'],
            db=REDIS_CONFIG['db'],
            password=REDIS_CONFIG['password'],
            decode_responses=REDIS_CONFIG['decode_responses']
        )
    except Exception as e:
        print(f"❌ Failed to connect to Redis: {e}")
        print("\n💡 Make sure Redis is running:")
        print("   brew services start redis  # macOS")
        print("   sudo systemctl start redis  # Linux")
        return 1
    
    # Prepare comprehensive rules dictionary
    rules_dict = get_all_rules()
    
    # Display rule statistics before loading
    print("\n📊 Rule Statistics:")
    stats = get_rule_statistics()
    print(f"   Total Categories: {stats['total_categories']}")
    print(f"   Total Rules: {stats['total_rules']}")
    print(f"\n   By Severity:")
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = stats['by_severity'][severity]
        if count > 0:
            print(f"      {severity:12} : {count:4} rules")
    
    # Initialize rules in Redis
    print("\n📝 Populating Redis with detection rules...")
    success = rule_manager.initialize_rules(rules_dict)
    
    if not success:
        print("❌ Failed to initialize rules")
        return 1
    
    # Display loaded rules by category
    print("\n✅ Rules loaded successfully by category:")
    counts = rule_manager.get_all_rule_counts()
    
    # Group by severity
    critical_rules = []
    high_rules = []
    medium_rules = []
    low_rules = []
    
    for category, count in counts.items():
        severity = SEVERITY_LEVELS.get(category, "LOW")
        entry = (category, count)
        if severity == "CRITICAL":
            critical_rules.append(entry)
        elif severity == "HIGH":
            high_rules.append(entry)
        elif severity == "MEDIUM":
            medium_rules.append(entry)
        else:
            low_rules.append(entry)
    
    if critical_rules:
        print("\n   🔴 CRITICAL:")
        for category, count in sorted(critical_rules, key=lambda x: x[1], reverse=True):
            print(f"      • {category.replace('_', ' ').title():40} : {count:3} patterns")
    
    if high_rules:
        print("\n   🟠 HIGH:")
        for category, count in sorted(high_rules, key=lambda x: x[1], reverse=True):
            print(f"      • {category.replace('_', ' ').title():40} : {count:3} patterns")
    
    if medium_rules:
        print("\n   🟡 MEDIUM:")
        for category, count in sorted(medium_rules, key=lambda x: x[1], reverse=True):
            print(f"      • {category.replace('_', ' ').title():40} : {count:3} patterns")
    
    if low_rules:
        print("\n   🟢 LOW:")
        for category, count in sorted(low_rules, key=lambda x: x[1], reverse=True):
            print(f"      • {category.replace('_', ' ').title():40} : {count:3} patterns")
    
    total = sum(count for _, count in counts.items())
    print(f"\n   📊 Total rules loaded: {total}")
    
    # OWASP Coverage
    print("\n🛡️  OWASP TOP 10 Coverage:")
    owasp_coverage = get_owasp_coverage()
    for owasp_cat, info in owasp_coverage.items():
        if info['total_rules'] > 0:
            print(f"   • {owasp_cat:50} : {info['total_rules']:3} rules")
    
    # Export backup
    backup_file = "rules_backup.json"
    print(f"\n💾 Creating backup at {backup_file}...")
    rule_manager.export_rules_to_json(backup_file)
    
    # Health check
    print("\n🏥 Health check:")
    health = rule_manager.health_check()
    print(f"   Status: {health['status'].upper()}")
    print(f"   Connected: {health['connected']}")
    print(f"   Total Rules: {health['total_rules']}")
    
    print("\n" + "=" * 80)
    print("✅ Redis initialization complete with comprehensive security rules!")
    print("=" * 80)
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
