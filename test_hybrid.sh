#!/bin/bash

# Test script for Hybrid WAF Server
# Tests various attack patterns to verify detection

PORT=8080
BASE_URL="http://localhost:${PORT}"

echo "🧪 Testing Enhanced Hybrid WAF Server"
echo "======================================"
echo ""

# Wait for server to be ready
echo "⏳ Checking if server is ready..."
for i in {1..30}; do
    if curl -s "${BASE_URL}/health" > /dev/null 2>&1; then
        echo "✅ Server is ready!"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "❌ Server not responding. Is it running on port ${PORT}?"
        exit 1
    fi
    sleep 1
done

echo ""
echo "Testing attack patterns..."
echo "=========================="

# Test 1: Path Traversal - /etc/passwd
echo ""
echo "🧪 Test 1: Path Traversal Attack - /etc/passwd"
curl -s "${BASE_URL}/etc/passwd" | jq -r '.blocked // "Request allowed"'

# Test 2: SQL Injection
echo ""
echo "🧪 Test 2: SQL Injection - OR 1=1"
curl -s "${BASE_URL}/search?q=%27%20OR%20%271%27=%271" | jq -r '.blocked // "Request allowed"'

# Test 3: Directory Traversal
echo ""
echo "🧪 Test 3: Directory Traversal - ../../etc/passwd"
curl -s "${BASE_URL}/../../etc/passwd" | jq -r '.blocked // "Request allowed"'

# Test 4: XSS Attack
echo ""
echo "🧪 Test 4: XSS Attack - <script>alert('XSS')</script>"
curl -s "${BASE_URL}/search?q=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E" | jq -r '.blocked // "Request allowed"'

# Test 5: Command Injection
echo ""
echo "🧪 Test 5: Command Injection - ; ls -la"
curl -s "${BASE_URL}/api/exec?cmd=test%3B%20ls%20-la" | jq -r '.blocked // "Request allowed"'

# Test 6: Benign request (should pass)
echo ""
echo "🧪 Test 6: Benign Request - Normal API call"
curl -s "${BASE_URL}/api/users" | jq -r '.message // "Request allowed"'

echo ""
echo ""
echo "📊 Getting WAF Statistics..."
echo "=========================="
curl -s "${BASE_URL}/waf/stats" | jq '.'

echo ""
echo ""
echo "📋 Recent Detection Logs (last 5)..."
echo "===================================="
curl -s "${BASE_URL}/waf/logs?count=5" | jq '.logs[] | "\(.timestamp) | \(.method) \(.path) | Malicious: \(.is_malicious) | Risk: \(.risk_level) | Method: \(.detection_method) | Threat: \(.threat_type)"'

echo ""
echo "✅ Testing Complete!"
