# 🧪 WAF Testing Framework - Quick Reference

## 🚀 Quick Start (5 Minutes)

```bash
# 1. Make scripts executable
chmod +x quick_start.sh test_curl.sh

# 2. Install Flask (if not already installed)
pip install flask

# 3. Run comprehensive tests
./quick_start.sh

# 4. Start real-time server for live testing
python3 test_server.py
```

---

## 📝 Testing Modes

### 1️⃣ Batch Testing (JSON Files)

Test multiple payloads at once and get detailed metrics:

```bash
# Test malicious payloads
python3 test_model.py --test-file test_payloads/malicious_payloads.json --output reports/malicious.json

# Test benign payloads
python3 test_model.py --test-file test_payloads/benign_payloads.json --output reports/benign.json

# Adjust detection sensitivity (90-99)
python3 test_model.py --test-file test_payloads/malicious_payloads.json --threshold 97
```

**Output:** JSON report with accuracy, precision, recall, F1-score, confusion matrix

### 2️⃣ Real-time Server Testing

Accept live HTTP requests (perfect for demos):

```bash
# Start server
python3 test_server.py

# In another terminal, test with curl
curl "http://localhost:5000/api/test?param=value"

# Monitor statistics
curl "http://localhost:5000/waf/stats" | python3 -m json.tool

# View detection logs
curl "http://localhost:5000/waf/logs"
```

### 3️⃣ Automated curl Testing

Run comprehensive test suite:

```bash
chmod +x test_curl.sh
./test_curl.sh
```

### 4️⃣ Interactive Testing

Test individual requests interactively:

```bash
python3 test_model.py --interactive

# Then paste JSON request:
> {"method": "GET", "path": "/test", "query": {"id": "1' OR '1'='1"}}
```

---

## 🎯 For Grand Finale Judges

### Option A: Submit JSON File

Create `judges_test.json`:

```json
{
  "requests": [
    {
      "method": "GET",
      "path": "/api/test",
      "query": { "param": "malicious_payload_here" },
      "headers": { "user-agent": "Mozilla/5.0" }
    }
  ],
  "labels": [1]
}
```

Run test:

```bash
python3 test_model.py --test-file judges_test.json --output judges_report.json
```

### Option B: Live curl Commands

Start server and submit curl requests:

```bash
# Terminal 1
python3 test_server.py

# Terminal 2
curl "http://localhost:5000/api/endpoint?param=<payload>"

# Check results
curl "http://localhost:5000/waf/stats"
```

### Option C: Use Test Script

```bash
./test_curl.sh  # Runs 15+ pre-configured test cases
```

---

## 📊 Understanding Results

### Detection Output

```json
{
  "is_malicious": true,
  "confidence": 87.3,
  "reconstruction_loss": 9.245,
  "risk_level": "HIGH",
  "anomaly_score": 4.52
}
```

- **is_malicious**: Boolean detection result
- **confidence**: 0-100% confidence in detection
- **reconstruction_loss**: Model's reconstruction error (higher = more anomalous)
- **risk_level**: LOW | MEDIUM | HIGH | CRITICAL
- **anomaly_score**: Statistical deviation from baseline (Z-score)

### Risk Levels

- 🟢 **LOW**: Normal traffic (< 95th percentile)
- 🟡 **MEDIUM**: Slightly unusual (95-99th percentile)
- 🟠 **HIGH**: Anomalous (> threshold, < 1.5x)
- 🔴 **CRITICAL**: Severe anomaly (> 1.5x threshold)

---

## 🛠️ Common Commands

```bash
# Generate custom payloads
python3 generate_payloads.py --type sql --output-dir my_tests

# Test with custom model
python3 test_model.py --model models/custom_model --test-file test.json

# Start server on different port
python3 test_server.py --port 8080

# Stricter detection (fewer false positives)
python3 test_model.py --threshold 99 --test-file payloads.json

# More sensitive detection (catches more attacks)
python3 test_model.py --threshold 92 --test-file payloads.json

# Export server logs
curl http://localhost:5000/waf/export -o logs.json
```

---

## 📁 Files & Directories

```
deberta/
├── test_model.py              # Batch testing script
├── test_server.py             # Real-time HTTP server
├── test_curl.sh               # Automated curl tests
├── generate_payloads.py       # Payload generator
├── quick_start.sh             # Quick setup script
├── TESTING_GUIDE.md           # Comprehensive guide
├── test_payloads/             # Test payload files
│   ├── malicious_payloads.json
│   └── benign_payloads.json
├── reports/                   # Test reports output
└── src/
    └── detector.py            # Detection engine
```

---

## 🔧 Troubleshooting

**Model not found:**

```bash
# Check model exists
ls models/deberta-waf/best_model/

# Should see: config.json, model.safetensors
```

**Flask not installed:**

```bash
pip install flask
```

**Too many false positives:**

```bash
# Increase threshold (stricter)
python3 test_model.py --threshold 98 --test-file test.json
```

**Missing attacks:**

```bash
# Decrease threshold (more sensitive)
python3 test_model.py --threshold 93 --test-file test.json
```

---

## 🎓 Example Testing Session

```bash
# Step 1: Start server
python3 test_server.py
# ✅ WAF Server Ready on http://0.0.0.0:5000

# Step 2: Test benign request (in another terminal)
curl "http://localhost:5000/api/products?category=electronics"
# ✅ BENIGN - Risk Level: LOW

# Step 3: Test SQL injection
curl "http://localhost:5000/search?q=1' UNION SELECT * FROM users--"
# 🚨 MALICIOUS - Risk Level: CRITICAL - HTTP 403 BLOCKED

# Step 4: View statistics
curl http://localhost:5000/waf/stats | python3 -m json.tool
# {
#   "total_requests": 2,
#   "malicious_count": 1,
#   "detection_rate": 50.0
# }

# Step 5: Run full test suite
./test_curl.sh
# Runs 15+ test cases automatically

# Step 6: Generate comprehensive report
python3 test_model.py --test-file test_payloads/malicious_payloads.json --output final_report.json
```

---

## 📈 Metrics Explained

- **Accuracy**: (TP + TN) / Total - Overall correctness
- **Precision**: TP / (TP + FP) - Accuracy of positive predictions
- **Recall**: TP / (TP + FN) - Coverage of actual attacks
- **F1-Score**: Harmonic mean of precision and recall
- **Detection Rate**: Percentage of requests flagged as malicious
- **False Positive Rate**: Benign requests incorrectly flagged

---

## 🎯 Key Features

✅ **Zero-day detection** - Never trained on attacks  
✅ **Anomaly-based** - Grammar understanding, not signatures  
✅ **Real-time** - Low latency (<200ms)  
✅ **Explainable** - Confidence scores and risk levels  
✅ **Comprehensive** - Tests SQL, XSS, Command Injection, etc.

---

## 📞 Need Help?

1. Read **TESTING_GUIDE.md** for detailed documentation
2. Check model training logs: `models/deberta-waf/training_history.json`
3. Verify calibration on startup (baseline statistics shown)
4. Adjust threshold: 90-99 range (`--threshold` parameter)

---

**Ready to Test! 🚀**

For detailed documentation, see [TESTING_GUIDE.md](TESTING_GUIDE.md)
