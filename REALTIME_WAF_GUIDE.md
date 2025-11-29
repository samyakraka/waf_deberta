# Real-Time WAF Monitoring System

This system monitors real logs from three vulnerable web applications (DVWA, Juice Shop, WebGoat) using Docker and Nginx, and classifies each incoming HTTP request in real-time as either **ATTACK** or **BENIGN** using a DeBERTa transformer-based WAF model.

## 🎯 Features

- **Real-Time Classification**: Streams logs to terminal and classifies each request instantly
- **Multi-Application Monitoring**: Simultaneously monitors DVWA, Juice Shop, and WebGoat
- **Color-Coded Output**: Visual distinction between attacks and benign traffic
- **Risk Level Assessment**: Shows LOW, MEDIUM, HIGH, or CRITICAL risk levels
- **Live Statistics**: Displays detection rates and counts
- **Zero-Day Detection**: Can detect novel attacks without signatures (trained only on benign traffic)

## 🏗️ Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│      DVWA       │     │   Juice Shop    │     │     WebGoat     │
│   (Port 8081)   │     │   (Port 3000)   │     │   (Port 8082)   │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │
         └───────────────────────┴───────────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   Nginx Reverse Proxy   │
                    │  (Ports 8080/8090/8091) │
                    │   Detailed Logging ON   │
                    └────────────┬────────────┘
                                 │
                      ┌──────────▼──────────┐
                      │   nginx/logs/*.log  │
                      └──────────┬──────────┘
                                 │
                    ┌────────────▼────────────┐
                    │  Real-Time Log Monitor  │
                    │  (Log Parser + Tailer)  │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   DeBERTa WAF Detector  │
                    │  (Anomaly Detection)    │
                    └────────────┬────────────┘
                                 │
                      ┌──────────▼──────────┐
                      │  Terminal Output    │
                      │  + JSON Results     │
                      └─────────────────────┘
```

## 📋 Prerequisites

1. **Docker Desktop** installed and running
2. **Python 3.8+** with virtual environment
3. **Trained DeBERTa WAF model** at `models/deberta-waf/best_model/`

## 🚀 Quick Start

### 1. Make Scripts Executable

```bash
chmod +x start_waf_system.sh stop_waf_system.sh
```

### 2. Start the System

```bash
./start_waf_system.sh
```

This script will:

- Start all Docker containers (DVWA, Juice Shop, WebGoat, Nginx)
- Wait for services to be ready
- Optionally start real-time monitoring

### 3. Access the Applications

**Via Nginx Proxy (WITH WAF Logging - Use these for testing):**

- DVWA: http://localhost:8080
- Juice Shop: http://localhost:8090
- WebGoat: http://localhost:8091/WebGoat/login

**Direct Access (No logging):**

- DVWA: http://localhost:8081
- Juice Shop: http://localhost:3000
- WebGoat: http://localhost:8082/WebGoat/login

### 4. Monitor Logs in Real-Time

If not started automatically:

```bash
python3 realtime_waf_monitor.py --model models/deberta-waf/best_model
```

### 5. Stop the System

```bash
./stop_waf_system.sh
```

## 🎨 Sample Output

```
================================================================================
🛡️  Real-Time WAF Monitor - DeBERTa Transformer
================================================================================

Loading WAF detector...
✓ Model loaded from models/deberta-waf/best_model
✓ Monitor initialized
✓ Watching 3 log files

================================================================================
Monitoring Applications:
  • DVWA: nginx/logs/dvwa-access.log
  • JuiceShop: nginx/logs/juiceshop-access.log
  • WebGoat: nginx/logs/webgoat-access.log
================================================================================

Timestamp            App          Method   Path                           Result          Confidence   Risk
----------------------------------------------------------------------------------------------------------------------------------
2025-11-29 10:30:45  DVWA         GET      /vulnerabilities/sqli/?id=1... 🚨 ATTACK       98.5%        CRITICAL
2025-11-29 10:30:50  JuiceShop    GET      /api/products                  ✓ BENIGN        95.2%        LOW
2025-11-29 10:31:00  WebGoat      POST     /WebGoat/attack                🚨 ATTACK       97.3%        HIGH
```

## 📁 Project Structure

```
deberta/
├── docker/
│   ├── docker-compose.yml        # Docker services configuration
│   └── nginx/
│       └── nginx.conf            # Nginx proxy configuration
├── nginx/
│   └── logs/                     # Generated log files (auto-created)
│       ├── dvwa-access.log
│       ├── juiceshop-access.log
│       └── webgoat-access.log
├── src/
│   ├── detector.py               # DeBERTa WAF detector
│   └── log_parser.py             # Nginx log parser
├── models/
│   └── deberta-waf/
│       └── best_model/           # Trained model files
├── realtime_waf_monitor.py       # Main monitoring script
├── start_waf_system.sh           # System startup script
├── stop_waf_system.sh            # System shutdown script
└── REALTIME_WAF_GUIDE.md         # This file
```

## ⚙️ Advanced Usage

### Custom Model Path

```bash
python3 realtime_waf_monitor.py --model /path/to/your/model
```

### Custom Logs Directory

```bash
python3 realtime_waf_monitor.py --logs-dir /path/to/logs
```

### Save Results to JSON

```bash
python3 realtime_waf_monitor.py --output results.json
```

### Calibrate with Benign Data

```bash
python3 realtime_waf_monitor.py --calibration data/benign_requests.json
```

### Monitor Only Specific Apps

Edit `log_files` dictionary in `realtime_waf_monitor.py`:

```python
log_files = {
    'DVWA': str(logs_dir / 'dvwa-access.log'),
    # Comment out apps you don't want to monitor
    # 'JuiceShop': str(logs_dir / 'juiceshop-access.log'),
    # 'WebGoat': str(logs_dir / 'webgoat-access.log'),
}
```

## 🧪 Testing Attack Detection

### SQL Injection (DVWA)

Visit: http://localhost:8080/vulnerabilities/sqli/?id=1' OR '1'='1

### XSS (Juice Shop)

Visit: http://localhost:8090/search?q=<script>alert('XSS')</script>

### Path Traversal (WebGoat)

Visit: http://localhost:8091/WebGoat/attack?file=../../../etc/passwd

## 📊 Understanding the Output

### Result Classification

- **🚨 ATTACK**: Request classified as malicious
- **✓ BENIGN**: Request classified as benign

### Risk Levels

- **LOW** (Green): Low anomaly score, likely benign
- **MEDIUM** (Yellow): Moderate anomaly, may warrant attention
- **HIGH** (Red): High anomaly score, likely attack
- **CRITICAL** (Magenta): Very high anomaly score, definite attack

### Confidence Score

- Percentage indicating model's confidence in the classification
- Higher percentage = more confident

## 🔧 Troubleshooting

### Docker containers not starting

```bash
cd docker
docker-compose logs
```

### Model not found

Train the model first:

```bash
python3 src/trainer.py --data data/tokenized/waf_benign_train.pt --epochs 5
```

### Logs not appearing

1. Check if containers are running:

   ```bash
   docker ps
   ```

2. Check if log files exist:

   ```bash
   ls -la nginx/logs/
   ```

3. Make test request through Nginx:
   ```bash
   curl http://localhost:8080
   ```

### Permission issues with logs

```bash
chmod -R 755 nginx/logs/
```

## 🎓 How It Works

1. **Log Collection**: Nginx captures detailed HTTP request information in custom format
2. **Log Tailing**: Python script monitors log files for new entries in real-time
3. **Parsing**: Each log line is parsed to extract request components (method, path, query, headers, body)
4. **Classification**: DeBERTa transformer model analyzes request and computes anomaly score
5. **Detection**: High reconstruction loss indicates anomaly → potential attack
6. **Display**: Results are color-coded and streamed to terminal with statistics

### Why This Approach?

- **Zero-Day Safe**: Model trained only on benign traffic, can detect novel attacks
- **Real-Time**: No polling or delays, instant classification as logs are written
- **Multi-App**: Monitors multiple applications simultaneously with threading
- **Transparent**: Shows exactly what's happening with each request

## 📝 Log Format

Nginx uses custom `waf_detailed` format:

```
$remote_addr - $remote_user [$time_local] "$request_method $scheme://$host$request_uri $server_protocol" $status $body_bytes_sent "$http_referer" "$http_user_agent" "$http_x_forwarded_for" request_time=$request_time upstream_response_time=$upstream_response_time request_body="$request_body" query_string="$query_string" content_type="$content_type" content_length="$content_length"
```

This captures:

- Client IP and timestamp
- Full request line (method, URL, protocol)
- Response status and size
- Headers (User-Agent, Referer)
- Request timing
- Request body (for POST/PUT)
- Query parameters
- Content metadata

## 🔒 Security Notes

- This is a **testing/research environment** with intentionally vulnerable applications
- **Do NOT** expose these services to the internet
- Use only in isolated networks or local development
- The vulnerable apps are for educational purposes only

## 📚 References

- [DeBERTa: Decoding-enhanced BERT with Disentangled Attention](https://arxiv.org/abs/2006.03654)
- [DVWA Documentation](https://github.com/digininja/DVWA)
- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)
- [WebGoat Documentation](https://owasp.org/www-project-webgoat/)

## 🤝 Contributing

Improvements welcome! Key areas:

- Additional log formats
- More vulnerable applications
- Enhanced parsing for complex payloads
- Performance optimizations
- Better visualization

## 📄 License

This project is for educational and research purposes.

---

**Happy Testing! 🛡️**
