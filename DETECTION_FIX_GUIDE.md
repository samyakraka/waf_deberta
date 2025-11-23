# WAF Detection Issues - Analysis & Solutions

## 🔍 Problem Analysis

Your WAF server is running but **not detecting malicious requests** like `/etc/passwd`. Here's why:

### Issue 1: Threshold Too High ❌

- **Current threshold**: 95th percentile
- **What this means**: Only requests more anomalous than 95% of benign traffic are flagged
- **Result**: Simple attacks like `/etc/passwd` fall below this threshold

Your logs show:

```json
{
  "path": "/etc/passwd",
  "reconstruction_loss": 4.339046115754172,
  "is_malicious": false,  // ❌ Should be true!
  "risk_level": "LOW",
  "confidence": 47.09%
}
```

The model's threshold is likely around 6-8, so loss of 4.34 doesn't trigger detection.

### Issue 2: Model Limitations 🧠

- **Training data**: Model was trained ONLY on benign HTTP requests
- **Problem**: Simple path-based attacks like `/etc/passwd` look structurally similar to normal paths like `/api/users`
- **The model sees**: Just another URL path with standard characters
- **ML blind spot**: Pure anomaly detection struggles with attacks that don't break HTTP grammar

### Issue 3: No Signature-Based Detection 🎯

- Your current system relies 100% on ML anomaly detection
- Many attacks (SQL injection, XSS, path traversal) have **known patterns**
- These can be caught with simple regex rules

---

## ✅ Solutions

### Solution 1: Lower Detection Threshold (Quick Fix)

**Change threshold from 95% to 80-85%**

**Files modified**: `test_server.py` (already done ✓)

```python
threshold_percentile=80.0  # More sensitive (was 95.0)
```

**Pros**:

- Easy to implement (1 line change)
- More sensitive to anomalies
- Will catch more attacks

**Cons**:

- May increase false positives
- Still misses obvious attack patterns

**To apply**: Restart your server - it now uses 80th percentile by default.

---

### Solution 2: Hybrid Detection (Recommended) ⭐

**Combine ML with rule-based pattern matching**

**New file**: `test_server_hybrid.py`

This approach uses:

1. **ML Anomaly Detection** - Catches novel/zero-day attacks
2. **Rule-Based Detection** - Catches known attack patterns

**Attack patterns detected**:

- ✅ Path Traversal: `/etc/passwd`, `../`, `%2e%2e`
- ✅ SQL Injection: `' OR '1'='1`, `UNION SELECT`
- ✅ XSS: `<script>`, `javascript:`, `onerror=`
- ✅ Command Injection: `; ls`, `| cat`, `$(whoami)`
- ✅ Encoding Evasion: `%00`, `%0d%0a`

**How it works**:

```python
# If rule catches it but ML doesn't → HIGH risk
# If both catch it → CRITICAL risk (high confidence)
# If only ML catches it → Use ML risk level
# If neither catches it → CLEAN
```

**To use**:

```bash
# Stop current server (Ctrl+C)

# Start hybrid server
source wafenv/bin/activate
python test_server_hybrid.py --port 8080 --threshold 85

# Test it
./test_hybrid.sh
```

---

### Solution 3: Very Low Threshold (Aggressive)

**Use 75th percentile threshold**

**Best for**: High-security environments where false positives are acceptable

```bash
python test_server_hybrid.py --port 8080 --threshold 75
```

**Warning**: May flag some legitimate requests as suspicious.

---

## 🧪 Testing Your Current Setup

### Quick Test Script

```bash
# Run this to test if /etc/passwd is now detected
source wafenv/bin/activate
python fix_detection.py
```

This will show you how different thresholds perform.

### Test with cURL

```bash
# Should be blocked now
curl http://localhost:8080/etc/passwd

# Check logs
curl http://localhost:8080/waf/logs?count=5 | jq
```

---

## 📊 Expected Results with Hybrid Detection

### Before (Current Setup):

```
✅ GET /etc/passwd - LOW (Loss: 4.34) ❌ NOT DETECTED
```

### After (Hybrid Detection):

```
🚨 GET /etc/passwd - HIGH (Loss: 4.34) ✅ DETECTED
   Risk: HIGH | Method: RULE | Confidence: 90.0%
   Threat: Path Traversal/LFI
   Response: 403 BLOCKED
```

---

## 🚀 Recommended Setup for Production

1. **Use Hybrid Detection** (`test_server_hybrid.py`)
2. **Set threshold to 85%** (balanced sensitivity)
3. **Enable blocking** for HIGH and CRITICAL risks
4. **Monitor false positives** and adjust threshold

### Start Command:

```bash
source wafenv/bin/activate
python test_server_hybrid.py \
  --port 8080 \
  --threshold 85 \
  --model-path models/deberta-waf/best_model
```

### Test All Attack Vectors:

```bash
./test_hybrid.sh
```

---

## 📈 Performance Comparison

| Attack Type   | Pure ML (95%) | ML (80%) | Hybrid (85%) |
| ------------- | ------------- | -------- | ------------ |
| `/etc/passwd` | ❌ Miss       | ⚠️ Maybe | ✅ Catch     |
| SQL Injection | ❌ Miss       | ⚠️ Maybe | ✅ Catch     |
| XSS           | ❌ Miss       | ⚠️ Maybe | ✅ Catch     |
| Zero-day      | ✅ Catch      | ✅ Catch | ✅ Catch     |
| Obfuscated    | ⚠️ Maybe      | ⚠️ Maybe | ✅ Catch     |

**Legend**: ✅ High detection | ⚠️ Moderate | ❌ Low detection

---

## 🔧 Troubleshooting

### Q: Still not detecting attacks?

**A**: Check calibration threshold:

```bash
grep "Anomaly Threshold" logs/server.log
```

### Q: Too many false positives?

**A**: Increase threshold:

```bash
python test_server_hybrid.py --threshold 90
```

### Q: Want to see all detections?

**A**: Check logs endpoint:

```bash
curl http://localhost:8080/waf/logs | jq
```

---

## 📝 Next Steps

1. ✅ **Immediate**: Restart server with hybrid detection
2. ⚡ **Test**: Run `./test_hybrid.sh` to verify detection
3. 📊 **Monitor**: Check `/waf/stats` endpoint for false positive rate
4. 🎯 **Tune**: Adjust threshold based on your traffic patterns
5. 🚀 **Deploy**: Use hybrid server for production

---

## 🎓 Key Takeaways

1. **Pure ML has limitations** - Can't catch all obvious attack patterns
2. **Hybrid approach is best** - Combines strengths of both methods
3. **Threshold matters** - 95% is too conservative for most use cases
4. **Test thoroughly** - Use provided test scripts to validate
5. **Monitor continuously** - Adjust based on real-world performance

---

## 🛠️ Files Created/Modified

- ✅ `test_server.py` - Updated threshold to 80%
- ✅ `test_server_hybrid.py` - New hybrid detection server
- ✅ `fix_detection.py` - Testing script for different thresholds
- ✅ `test_hybrid.sh` - Comprehensive attack testing
- ✅ `DETECTION_FIX_GUIDE.md` - This guide

---

**Need help?** Run `python fix_detection.py` to see different solutions in action!
