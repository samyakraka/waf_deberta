# DeBERTa WAF Detection System

A transformer-based Web Application Firewall detection system using Microsoft's DeBERTa model.

## Installation

```bash
# Create virtual environment
python3 -m venv wafenv
source wafenv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## How to Run

### Step 1: Parse Raw Data

```bash
python -c "from src.parser import RequestParser; parser = RequestParser(); parser.parse_file('data/raw/waf_benign.txt')"
```

### Step 2: Tokenize Data

```bash
python -c "from src.tokenizer import DeBERTaTokenizer; tokenizer = DeBERTaTokenizer(); tokenizer.prepare_dataset('data/parsed/parsed_requests.json')"
```

### Step 3: Train Model

```bash
python -c "from src.trainer import DeBERTaTrainer; trainer = DeBERTaTrainer(); trainer.train()"
```

## Configuration

Edit `config.py` to change model parameters, training settings, and data paths.

This will test:

- ✓ Log parser functionality
- ✓ DeBERTa tokenizer loading
- ✓ Trainer initialization with MPS
- ✓ Apple Silicon compatibility

---

## 🎯 Quick Start

### Run Complete Pipeline (Default Settings)

```bash
python pipeline.py
```

This will:

1. **Parse** all `.log` files in `logs/` directory
2. **Normalize** dynamic values (IDs, tokens, timestamps)
3. **Tokenize** using `microsoft/deberta-v3-small`
4. **Train** model for 5 epochs with MPS acceleration
5. **Save** trained model to `models/deberta-waf/`

### Custom Configuration

```bash
# Custom batch size and epochs
python pipeline.py --batch-size 32 --epochs 10

# Specific log files only
python pipeline.py --log-files logs/dvwa.log logs/juiceshop.log

# Custom output directories
python pipeline.py --output-dir results --model-dir my_model

# Disable MPS (use CPU)
python pipeline.py --no-mps

# Custom learning rate
python pipeline.py --learning-rate 3e-5
```

### View All Options

```bash
python pipeline.py --help
```

---

## 📊 Pipeline Stages

### Stage 1: Parsing & Normalization

**Input**: Raw Apache/Nginx access logs

**Process**:

- Extracts: method, path, query params, headers, body, status code
- Normalizes: UUIDs → `{uuid}`, IDs → `{id}`, tokens → `{token}`
- Removes: timestamps, dynamic values
- Preserves: request structure, parameter names
