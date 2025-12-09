#!/bin/bash
# Quick Start - Real-Time WAF Monitoring System
# Run this script to get started quickly

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║     Real-Time WAF Monitoring - Quick Start Guide              ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo

echo "📋 Prerequisites Check:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check Docker
if docker --version > /dev/null 2>&1; then
    echo "✓ Docker installed: $(docker --version)"
else
    echo "✗ Docker not found. Please install Docker Desktop first."
    exit 1
fi

# Check Python
if python3 --version > /dev/null 2>&1; then
    echo "✓ Python installed: $(python3 --version)"
else
    echo "✗ Python3 not found. Please install Python 3.8+."
    exit 1
fi

# Check virtual environment
if [ -d "wafenv" ]; then
    echo "✓ Virtual environment found"
else
    echo "⚠ Virtual environment not found at ./wafenv"
    echo "  Please ensure dependencies are installed"
fi

# Check model
if [ -d "models_30k/deberta-waf/best_model" ]; then
    echo "✓ WAF model found"
else
    echo "⚠ WAF model not found at models_30k/deberta-waf/best_model"
    echo "  You may need to train the model first"
fi

echo
echo "🚀 Quick Start Commands:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
echo "1. Start the complete system (Docker + Monitoring):"
echo "   ./start_waf_system.sh"
echo
echo "2. Or start step-by-step:"
echo "   # Start Docker containers"
echo "   cd docker && docker-compose up -d && cd .."
echo
echo "   # Activate Python environment (if using venv)"
echo "   source wafenv/bin/activate"
echo
echo "   # Start real-time monitoring"
echo "   python3 realtime_waf_monitor.py --model models_30k/deberta-waf/best_model"
echo
echo "3. Stop everything:"
echo "   ./stop_waf_system.sh"
echo
echo "🌐 Access Points (use these for WAF testing):"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  DVWA:       http://localhost:8080"
echo "  Juice Shop: http://localhost:8090"
echo "  WebGoat:    http://localhost:8091/WebGoat/login"
echo
echo "🧪 Test Attack Patterns:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  SQL Injection:"
echo "    curl 'http://localhost:8080/vulnerabilities/sqli/?id=1%27%20OR%20%271%27=%271'"
echo
echo "  XSS:"
echo "    curl 'http://localhost:8090/search?q=<script>alert(1)</script>'"
echo
echo "  Path Traversal:"
echo "    curl 'http://localhost:8091/attack?file=../../../etc/passwd'"
echo
echo "📚 Documentation:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Full guide: REALTIME_WAF_GUIDE.md"
echo
echo "═══════════════════════════════════════════════════════════════════"
echo "Ready to start! Run: ./start_waf_system.sh"
echo "═══════════════════════════════════════════════════════════════════"
