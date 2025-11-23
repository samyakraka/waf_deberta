# 🛡️ DeBERTa WAF Testing Guide

## Grand Finale Testing Framework

This testing framework is designed for evaluating the DeBERTa-based WAF model's ability to detect malicious payloads in real-time, suitable for judges' evaluation during the grand finale.

---

## 📋 Overview

The testing framework includes:

1. **Anomaly Detector** (`src/detector.py`) - Core detection engine using reconstruction loss
2. **Batch Testing** (`test_model.py`) - Test from JSON files with detailed reports
3. **Real-time Server** (`test_server.py`) - Flask server for live curl-based testing
4. **Automated Testing** (`test_curl.sh`) - Bash script with pre-configured test cases

---

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip install flask
```

### 2. Test from JSON Files (Batch Testing)

```bash
# Test malicious payloads
python3 test_model.py --test-file test_payloads/malicious_payloads.json --output reports/malicious_report.json

# Test benign payloads
python3 test_model.py --test-file test_payloads/benign_payloads.json --output reports/benign_report.json

# Adjust sensitivity (95-99)
python3 test_model.py --test-file test_payloads/malicious_payloads.json --threshold 97
```

### 3. Start Real-time Testing Server

```bash
# Start server (default: http://localhost:5000)
python test_server.py

# Custom configuration
python test_server.py --host 0.0.0.0 --port 8080 --threshold 95
```

### 4. Test with curl Commands

```bash
# Make script executable
chmod +x test_curl.sh

# Run automated tests
./test_curl.sh

# Or test individual payloads
curl "http://localhost:5000/search?q=<script>alert('XSS')</script>"
```

---

## 📊 Testing Modes

### Mode 1: Batch Testing (JSON Files)

**Best for:** Comprehensive evaluation with metrics (accuracy, precision, recall)

```bash
python test_model.py --test-file test_payloads/malicious_payloads.json --output report.json
```

**Output includes:**

- Detection rate
- Risk level distribution
- Accuracy, Precision, Recall, F1-Score (if labels provided)
- Detailed per-request analysis
- Confidence scores and anomaly scores

**Example JSON format:**

```json
{
  "requests": [
    {
      "method": "GET",
      "path": "/search",
      "query": { "q": "<script>alert('XSS')</script>" },
      "headers": { "user-agent": "Mozilla/5.0" }
    }
  ],
  "labels": [1]
}
```

### Mode 2: Interactive Testing

**Best for:** Quick testing and debugging

```bash
python test_model.py --interactive
```

Commands:

- Paste JSON request directly
- Type `file <path>` to test from file
- Type `quit` to exit

### Mode 3: Real-time Server Testing

**Best for:** Grand Finale demonstration with live curl requests

```bash
# Terminal 1: Start server
python test_server.py

# Terminal 2: Send requests
curl "http://localhost:5000/api/test"
curl -X POST "http://localhost:5000/login" -H "Content-Type: application/json" -d '{"username":"admin","password":"test"}'
```

**Monitoring endpoints:**

- `http://localhost:5000/waf/stats` - Real-time statistics
- `http://localhost:5000/waf/logs` - Detection logs
- `http://localhost:5000/waf/export` - Export all logs

---

## 🎯 For Judges: Testing Protocol

### Step 1: Model Calibration

The model automatically calibrates using benign training data to establish baseline behavior.

### Step 2: Submit Test Payloads

Judges can submit payloads in three ways:

#### Option A: JSON File

```bash
# Create judges_payloads.json
{
  "requests": [
    {"method": "GET", "path": "/test", "query": {"param": "value"}},
    ...
  ],
  "labels": [0, 1, 1, 0, ...]  # Optional: 0=benign, 1=malicious
}

# Run test
python test_model.py --test-file judges_payloads.json --output judges_report.json
```

#### Option B: curl Commands (Live Demo)

```bash
# Start server
python test_server.py --port 5000

# Submit curl commands
curl "http://localhost:5000/api/endpoint?param=malicious_payload"

# Check results
curl "http://localhost:5000/waf/stats" | python3 -m json.tool
```

#### Option C: Automated Script

```bash
# Edit test_curl.sh with judge's payloads
./test_curl.sh
```

### Step 3: Evaluate Results

**Metrics provided:**

- **Accuracy**: Overall correctness
- **Precision**: True malicious / Detected malicious
- **Recall**: True malicious detected / Total malicious
- **F1-Score**: Harmonic mean of precision and recall
- **Detection Rate**: Percentage of requests flagged
- **False Positive Rate**: Benign requests flagged as malicious
- **False Negative Rate**: Malicious requests missed

---

## 🧪 Test Payload Categories

### Included Malicious Payloads

1. **SQL Injection**

   - UNION-based
   - Boolean-based blind
   - Time-based blind

2. **Cross-Site Scripting (XSS)**

   - Reflected XSS
   - DOM-based XSS
   - Stored XSS patterns

3. **Command Injection**

   - Shell command injection
   - Code execution attempts

4. **Path Traversal**

   - Directory traversal
   - File inclusion

5. **XXE (XML External Entity)**

   - File disclosure
   - SSRF via XXE

6. **NoSQL Injection**

   - MongoDB query injection
   - Operator injection

7. **Server-Side Template Injection (SSTI)**

8. **SSRF (Server-Side Request Forgery)**

9. **LDAP Injection**

10. **Prototype Pollution**

### Included Benign Payloads

- Normal GET/POST requests
- API calls (REST/JSON)
- Form submissions
- File downloads
- Search queries
- Authentication requests

---

## 📈 Understanding Results

### Detection Output

For each request, the system provides:

```json
{
  "is_malicious": true,
  "confidence": 85.4,
  "reconstruction_loss": 8.234,
  "anomaly_score": 4.21,
  "risk_level": "HIGH",
  "details": {
    "avg_loss": 8.234,
    "threshold": 6.123,
    "z_score": 4.21,
    "baseline_mean": 3.456,
    "baseline_std": 1.134
  }
}
```

**Risk Levels:**

- **LOW**: Loss < 95th percentile (likely benign)
- **MEDIUM**: Loss between 95th-99th percentile
- **HIGH**: Loss > threshold but < 1.5x threshold
- **CRITICAL**: Loss > 1.5x threshold (severe anomaly)

### How Detection Works

1. **Model Training**: Trained ONLY on benign HTTP traffic using Masked Language Modeling (MLM)
2. **Baseline Establishment**: Calibrate on known benign requests to set threshold
3. **Anomaly Detection**:
   - Mask random tokens in incoming request
   - Model tries to predict masked tokens
   - High reconstruction loss = Request grammar is unusual = Likely malicious
4. **Zero-Day Capability**: Never seen attack patterns, so can detect novel exploits

---

## 🎛️ Configuration Options

### Threshold Adjustment

```bash
# Stricter (fewer false positives, may miss some attacks)
python test_model.py --threshold 99

# Balanced (recommended)
python test_model.py --threshold 95

# More sensitive (catches more attacks, more false positives)
python test_model.py --threshold 90
```

### Server Configuration

```bash
python test_server.py \
    --model models/deberta-waf/best_model \
    --calibration data/parsed/parsed_requests.json \
    --threshold 95 \
    --host 0.0.0.0 \
    --port 5000
```

---

## 📝 Example Testing Session

```bash
# 1. Start server
python test_server.py

# 2. Test benign request
curl "http://localhost:5000/api/products?category=electronics"
# ✅ BENIGN - Risk Level: LOW

# 3. Test SQL injection
curl "http://localhost:5000/api/products?id=1' UNION SELECT password FROM users--"
# 🚨 MALICIOUS - Risk Level: CRITICAL - HTTP 403 BLOCKED

# 4. Check statistics
curl "http://localhost:5000/waf/stats"
# Output:
# {
#   "total_requests": 2,
#   "malicious_count": 1,
#   "benign_count": 1,
#   "detection_rate": 50.0
# }

# 5. View detailed logs
curl "http://localhost:5000/waf/logs?limit=10"

# 6. Export for analysis
curl "http://localhost:5000/waf/export" -o test_results.json
```

---

## 🔧 Troubleshooting

### Issue: Model not loading

```bash
# Verify model path
ls models/deberta-waf/best_model/
# Should contain: config.json, model.safetensors

# Use correct path
python test_model.py --model models/deberta-waf/best_model
```

### Issue: Calibration file not found

```bash
# Check calibration data exists
ls data/parsed/parsed_requests.json

# Use alternative calibration data if needed
python test_model.py --calibration path/to/benign_data.json
```

### Issue: Too many false positives

```bash
# Increase threshold (stricter)
python test_model.py --threshold 97
python test_server.py --threshold 97
```

### Issue: Missing some attacks

```bash
# Decrease threshold (more sensitive)
python test_model.py --threshold 93
python test_server.py --threshold 93
```

---

## 📊 Creating Custom Test Sets

### Format for Test Payloads

```json
{
  "description": "Custom test set",
  "requests": [
    {
      "name": "Optional description",
      "method": "GET|POST|PUT|DELETE",
      "path": "/endpoint/path",
      "query": {
        "param1": "value1",
        "param2": "value2"
      },
      "headers": {
        "content-type": "application/json",
        "user-agent": "Custom Agent"
      },
      "body": "Request body content"
    }
  ],
  "labels": [0, 1, 1, 0]
}
```

### Tips for Creating Test Cases

1. **Include variety**: Mix different attack types
2. **Test edge cases**: Encoded payloads, mixed attacks
3. **Include benign**: Test false positive rate
4. **Real-world scenarios**: Use actual application endpoints
5. **Obfuscation**: Test URL encoding, base64, Unicode

---

## 🏆 Grand Finale Demonstration

### Recommended Flow

1. **Setup** (5 min)

   - Start test server
   - Show system architecture
   - Explain zero-day detection capability

2. **Benign Traffic** (2 min)

   - Demonstrate normal requests pass through
   - Show low risk scores

3. **Attack Simulation** (5 min)

   - Submit various attack payloads
   - Show real-time blocking
   - Display confidence scores

4. **Judge's Custom Payloads** (10 min)

   - Accept judge-provided test cases
   - Live detection demonstration
   - Immediate result feedback

5. **Metrics Review** (3 min)
   - Show detection statistics
   - Display accuracy metrics
   - Export detailed report

### Key Talking Points

- ✅ **Zero-day detection**: Never trained on attacks
- ✅ **Anomaly-based**: Uses grammar understanding, not signatures
- ✅ **Transformer-powered**: DeBERTa v3 architecture
- ✅ **Real-time**: Low latency detection
- ✅ **Explainable**: Provides confidence scores and risk levels

---

## 📁 Output Files

### Report Structure

```
reports/
├── malicious_report.json    # Malicious payload test results
├── benign_report.json        # Benign payload test results
└── judges_report.json        # Grand finale evaluation
```

### Log Format

Each detection log contains:

- Timestamp
- Client IP
- Request details (method, path, query, headers, body)
- Detection result (malicious/benign)
- Risk level
- Confidence score
- Reconstruction loss
- Anomaly score

---

## 🔐 Security Notes

- Model detects anomalies, not specific attack types
- Threshold tuning affects false positive/negative rates
- Regular recalibration recommended for production
- Combine with traditional WAF rules for defense-in-depth

---

## 📞 Support

For issues or questions during testing:

- Check model training logs: `models/deberta-waf/training_history.json`
- Verify calibration: Detector shows baseline statistics on startup
- Adjust threshold: Use `--threshold` parameter (90-99 range)

---

## 🎓 Technical Details

**Architecture:**

- Model: microsoft/deberta-v3-small
- Training: Masked Language Modeling (MLM) on benign traffic only
- Detection: Reconstruction loss + statistical anomaly detection
- Threshold: Percentile-based (typically 95th-99th)

**Performance:**

- Detection latency: ~50-200ms per request
- Throughput: ~10-20 requests/second (CPU)
- Memory usage: ~2GB (model loaded)

---

**Ready for Testing! 🚀**
