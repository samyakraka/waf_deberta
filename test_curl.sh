#!/bin/bash

# WAF Testing Script using curl
# Tests both benign and malicious payloads
# For Grand Finale demonstration

SERVER="http://localhost:8080"
BOLD='\033[1m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=================================================="
echo "🛡️  DeBERTa WAF Testing Script"
echo "=================================================="
echo ""
echo "Server: $SERVER"
echo ""

# Function to test a request
test_request() {
    local name="$1"
    local cmd="$2"
    local expected="$3"
    
    echo -e "${BOLD}Testing: $name${NC}"
    echo "Command: $cmd"
    echo ""
    
    response=$(eval "$cmd" 2>&1)
    http_code=$(echo "$cmd" | sed 's/-s//' | eval "$(cat -) -w '%{http_code}'" 2>&1 | tail -n1)
    
    echo "Response:"
    echo "$response" | head -20
    echo ""
    
    if [ "$expected" = "blocked" ] && [ "$http_code" = "403" ]; then
        echo -e "${RED}✓ BLOCKED as expected${NC}"
    elif [ "$expected" = "allowed" ] && [ "$http_code" = "200" ]; then
        echo -e "${GREEN}✓ ALLOWED as expected${NC}"
    else
        echo -e "${YELLOW}⚠ Unexpected result (HTTP $http_code)${NC}"
    fi
    
    echo "--------------------------------------------------"
    echo ""
    sleep 1
}

echo "=================================================="
echo "🟢 BENIGN REQUESTS (Should be ALLOWED)"
echo "=================================================="
echo ""

# Test 1: Normal GET request
test_request \
    "Normal GET Request" \
    "curl -s '$SERVER/api/products?category=electronics&page=1' -H 'User-Agent: Mozilla/5.0'" \
    "allowed"

# Test 2: Normal POST request
test_request \
    "Normal POST Request" \
    "curl -s -X POST '$SERVER/api/users' -H 'Content-Type: application/json' -d '{\"username\":\"john\",\"email\":\"john@example.com\"}'" \
    "allowed"

# Test 3: Search query
test_request \
    "Search Query" \
    "curl -s '$SERVER/search?q=laptop+computers'" \
    "allowed"

# Test 4: API authentication
test_request \
    "API Authentication" \
    "curl -s -X POST '$SERVER/login' -H 'Content-Type: application/json' -d '{\"username\":\"user@example.com\",\"password\":\"securePass123\"}'" \
    "allowed"

echo ""
echo "=================================================="
echo "🔴 MALICIOUS REQUESTS (Should be BLOCKED)"
echo "=================================================="
echo ""

# Test 5: SQL Injection - UNION
test_request \
    "SQL Injection (UNION)" \
    "curl -s '$SERVER/api/products?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--'" \
    "blocked"

# Test 6: SQL Injection - Boolean blind
test_request \
    "SQL Injection (Boolean-based)" \
    "curl -s -X POST '$SERVER/login' -H 'Content-Type: application/json' -d '{\"username\":\"admin'\'' AND '\''1'\''='\''1\",\"password\":\"anything\"}'" \
    "blocked"

# Test 7: XSS - Script injection
test_request \
    "XSS Attack (Script Tag)" \
    "curl -s '$SERVER/search?q=%3Cscript%3Ealert(%27XSS%27)%3C/script%3E'" \
    "blocked"

# Test 8: XSS - Image onerror
test_request \
    "XSS Attack (Image onerror)" \
    "curl -s '$SERVER/search?q=%3Cimg%20src=x%20onerror=alert(document.cookie)%3E'" \
    "blocked"

# Test 9: Command Injection
test_request \
    "Command Injection" \
    "curl -s -X POST '$SERVER/api/test' -H 'Content-Type: application/json' -d '{\"host\":\"8.8.8.8; cat /etc/passwd\"}'" \
    "blocked"

# Test 10: Path Traversal
test_request \
    "Path Traversal" \
    "curl -s '$SERVER/api/test?file=../../../../etc/passwd'" \
    "blocked"

# Test 11: XXE Attack
test_request \
    "XXE Attack" \
    "curl -s -X POST '$SERVER/api/test' -H 'Content-Type: application/xml' -d '<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM \"file:///etc/passwd\">]><root>&test;</root>'" \
    "blocked"

# Test 12: NoSQL Injection
test_request \
    "NoSQL Injection" \
    "curl -s -X POST '$SERVER/login' -H 'Content-Type: application/json' -d '{\"username\":{\"\$ne\":null},\"password\":{\"\$ne\":null}}'" \
    "blocked"

# Test 13: SSRF Attack
test_request \
    "SSRF Attack" \
    "curl -s -X POST '$SERVER/api/test' -H 'Content-Type: application/json' -d '{\"url\":\"http://169.254.169.254/latest/meta-data/\"}'" \
    "blocked"

# Test 14: Template Injection
test_request \
    "Template Injection" \
    "curl -s '$SERVER/search?q={{7*7}}'" \
    "blocked"

echo ""
echo "=================================================="
echo "📊 Get WAF Statistics"
echo "=================================================="
echo ""
curl -s "$SERVER/waf/stats" | python3 -m json.tool

echo ""
echo "=================================================="
echo "✅ Testing Complete!"
echo "=================================================="
echo ""
echo "View detailed logs: curl $SERVER/waf/logs"
echo "Export logs: curl $SERVER/waf/export -o waf_logs.json"
echo ""
