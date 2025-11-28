#!/bin/bash

echo "=========================================="
echo "🧪 Testing Hierarchical WAF Server"
echo "=========================================="

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Base URL
BASE_URL="http://localhost:8080"

echo ""
echo "${YELLOW}1. Health Check${NC}"
curl -s "${BASE_URL}/health" | jq . || echo "Server not responding"

echo ""
echo "${YELLOW}2. Benign Request - Normal User Query${NC}"
curl -s "${BASE_URL}/api/user?id=123" | jq .

echo ""
echo "${YELLOW}3. Malicious Request - SQL Injection (OR 1=1)${NC}"
curl -s "${BASE_URL}/login?user=admin'%20OR%20'1'='1" | jq .

echo ""
echo "${YELLOW}4. Malicious Request - SQL Injection (UNION SELECT)${NC}"
curl -s "${BASE_URL}/search?q=test'%20UNION%20SELECT%20*%20FROM%20users--" | jq .

echo ""
echo "${YELLOW}5. Malicious Request - XSS Attack${NC}"
curl -s "${BASE_URL}/comment?text=<script>alert('XSS')</script>" | jq .

echo ""
echo "${YELLOW}6. Malicious Request - Path Traversal${NC}"
curl -s "${BASE_URL}/files?path=../../etc/passwd" | jq .

echo ""
echo "${YELLOW}7. Malicious Request - Command Injection${NC}"
curl -s "${BASE_URL}/exec?cmd=ls;cat%20/etc/passwd" | jq .

echo ""
echo "${YELLOW}8. Benign Request - Search Query${NC}"
curl -s "${BASE_URL}/search?q=hello%20world" | jq .

echo ""
echo "${YELLOW}9. View Statistics${NC}"
curl -s "${BASE_URL}/waf/stats" | jq .

echo ""
echo "${YELLOW}10. View Recent Logs (last 5)${NC}"
curl -s "${BASE_URL}/waf/logs?count=5" | jq .

echo ""
echo "=========================================="
echo "✅ Testing Complete!"
echo "=========================================="
