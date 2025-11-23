#!/bin/bash

# Quick Start Script for WAF Testing
# Runs initial tests to verify everything works

set -e

BOLD='\033[1m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BOLD}=================================================="
echo "🛡️  DeBERTa WAF - Quick Start Testing"
echo -e "==================================================${NC}"
echo ""

# Check if model exists
if [ ! -d "models/deberta-waf/best_model" ]; then
    echo -e "${YELLOW}⚠️  Warning: Trained model not found at models/deberta-waf/best_model${NC}"
    echo "Please ensure you have trained the model first using:"
    echo "  python3 src/trainer.py data/tokenized/waf_benign_train.pt data/tokenized/waf_benign_val.pt"
    exit 1
fi

# Check if calibration data exists
if [ ! -f "data/parsed/parsed_requests.json" ]; then
    echo -e "${YELLOW}⚠️  Warning: Calibration data not found${NC}"
    exit 1
fi

# Check if Flask is installed
if ! python3 -c "import flask" 2>/dev/null; then
    echo -e "${YELLOW}Installing Flask for server testing...${NC}"
    pip install flask
fi

echo -e "${GREEN}✓ Prerequisites verified${NC}"
echo ""

# Step 1: Generate test payloads
echo -e "${BLUE}${BOLD}Step 1: Generating test payloads${NC}"
python3 generate_payloads.py --output-dir test_payloads --type all
echo ""

# Step 2: Test with malicious payloads
echo -e "${BLUE}${BOLD}Step 2: Testing with malicious payloads${NC}"
mkdir -p reports
python3 test_model.py \
    --test-file test_payloads/comprehensive_malicious.json \
    --output reports/malicious_report.json \
    --threshold 95
echo ""

# Step 3: Test with benign payloads
echo -e "${BLUE}${BOLD}Step 3: Testing with benign payloads${NC}"
python3 test_model.py \
    --test-file test_payloads/comprehensive_benign.json \
    --output reports/benign_report.json \
    --threshold 95
echo ""

# Step 4: Display summary
echo -e "${BLUE}${BOLD}Step 4: Test Summary${NC}"
echo ""

if command -v python3 &> /dev/null; then
    python3 << 'EOF'
import json

print("📊 Malicious Payload Detection:")
with open('reports/malicious_report.json', 'r') as f:
    report = json.load(f)
    summary = report['summary']
    print(f"   Total: {summary['total_requests']}")
    print(f"   Detected: {summary['malicious_detected']} ({summary['detection_rate']:.1f}%)")
    if 'evaluation' in report:
        eval_data = report['evaluation']
        print(f"   Accuracy: {eval_data['accuracy']:.3f}")
        print(f"   Precision: {eval_data['precision']:.3f}")
        print(f"   Recall: {eval_data['recall']:.3f}")
        print(f"   F1-Score: {eval_data['f1_score']:.3f}")

print("\n📊 Benign Payload Detection:")
with open('reports/benign_report.json', 'r') as f:
    report = json.load(f)
    summary = report['summary']
    print(f"   Total: {summary['total_requests']}")
    print(f"   False Positives: {summary['malicious_detected']}")
    print(f"   Correctly Identified: {summary['benign_detected']}")
    if 'evaluation' in report:
        eval_data = report['evaluation']
        print(f"   Accuracy: {eval_data['accuracy']:.3f}")
EOF
fi

echo ""
echo -e "${GREEN}${BOLD}✅ Quick start testing complete!${NC}"
echo ""
echo "Next steps:"
echo "  1. Review detailed reports in reports/ directory"
echo "  2. Start real-time server: python3 test_server.py"
echo "  3. Run curl tests: ./test_curl.sh"
echo "  4. Interactive testing: python3 test_model.py --interactive"
echo ""
echo "See TESTING_GUIDE.md for complete documentation"
echo ""
