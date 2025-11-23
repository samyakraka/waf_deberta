#!/bin/bash

# Test script for custom external URLs through WAF proxy
# Tests how WAF handles various benign external API calls

PORT=8080
BASE_URL="http://localhost:${PORT}"

echo "🧪 Testing WAF with Custom External URLs"
echo "=========================================="
echo ""

# Wait for server to be ready
echo "⏳ Checking if server is ready..."
for i in {1..10}; do
    if curl -s "${BASE_URL}/health" > /dev/null 2>&1; then
        echo "✅ Server is ready!"
        break
    fi
    if [ $i -eq 10 ]; then
        echo "❌ Server not responding. Is it running on port ${PORT}?"
        exit 1
    fi
    sleep 1
done

echo ""
echo "Testing Custom URL Patterns..."
echo "=============================="
echo ""

# Test 1: Simple API call pattern
echo "🧪 Test 1: JSONPlaceholder API Pattern"
echo "Pattern: /todos/1"
curl -s "${BASE_URL}/todos/1" | jq '.'

echo ""
echo "🧪 Test 2: File Download Pattern (with extension)"
echo "Pattern: /image.png"
curl -s "${BASE_URL}/image.png" | jq '.'

echo ""
echo "🧪 Test 3: Weather API with Query Parameters"
echo "Pattern: /api/current.json?q=Nashik"
curl -s "${BASE_URL}/api/current.json?q=Nashik" | jq '.'

echo ""
echo "🧪 Test 4: Timezone API Pattern"
echo "Pattern: /api/timezone/Asia/Kolkata"
curl -s "${BASE_URL}/api/timezone/Asia/Kolkata" | jq '.'

echo ""
echo "🧪 Test 5: IP Geolocation API Pattern"
echo "Pattern: /json"
curl -s "${BASE_URL}/json" | jq '.'

echo ""
echo "🧪 Test 6: Geocode Search with Query"
echo "Pattern: /search?q=Nashik"
curl -s "${BASE_URL}/search?q=Nashik" | jq '.'

echo ""
echo "🧪 Test 7: Large ISO File Path"
echo "Pattern: /download/fedora/linux/releases/40/Workstation/x86_64/iso/Fedora-Workstation-Live-x86_64-40-1.14.iso"
curl -s "${BASE_URL}/download/fedora/linux/releases/40/Workstation/x86_64/iso/Fedora-Workstation-Live-x86_64-40-1.14.iso" | jq '.'

echo ""
echo "🧪 Test 8: REST API with ID Pattern"
echo "Pattern: /api/users/123"
curl -s "${BASE_URL}/api/users/123" | jq '.'

echo ""
echo "🧪 Test 9: Search with Normal Query"
echo "Pattern: /api/search?term=hello%20world"
curl -s "${BASE_URL}/api/search?term=hello%20world" | jq '.'

echo ""
echo "🧪 Test 10: API with Multiple Query Parameters"
echo "Pattern: /api/products?category=electronics&sort=price"
curl -s "${BASE_URL}/api/products?category=electronics&sort=price" | jq '.'

echo ""
echo ""
echo "📊 Getting WAF Statistics..."
echo "=========================="
curl -s "${BASE_URL}/waf/stats" | jq '.'

echo ""
echo ""
echo "📋 Recent Detection Logs (last 10)..."
echo "===================================="
curl -s "${BASE_URL}/waf/logs?count=10" | jq -r '.logs[] | "\(.timestamp) | \(.method) \(.path) | Blocked: \(.is_malicious) | Risk: \(.risk_level) | Method: \(.detection_method)"'

echo ""
echo "✅ Testing Complete!"
echo ""
