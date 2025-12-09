#!/bin/bash
# Start WAF Real-Time Monitoring System
# This script starts Docker containers and begins real-time log monitoring

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     WAF Real-Time Monitoring System - DeBERTa Transformer     ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}✗ Docker is not running. Please start Docker first.${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Docker is running${NC}"

# Check if model exists
MODEL_PATH="models_30k/deberta-waf/best_model"
if [ ! -d "$MODEL_PATH" ]; then
    echo -e "${YELLOW}⚠ Warning: Model not found at $MODEL_PATH${NC}"
    echo -e "${YELLOW}  You may need to train the model first.${NC}"
    echo
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Create logs directory if it doesn't exist
mkdir -p nginx/logs

echo -e "${BLUE}Starting Docker containers...${NC}"
cd docker
docker-compose up -d

# Wait for containers to be ready
echo -e "${YELLOW}Waiting for services to be ready...${NC}"
sleep 5

# Check if containers are running
if docker-compose ps | grep -q "Up"; then
    echo -e "${GREEN}✓ All containers are running${NC}"
else
    echo -e "${RED}✗ Some containers failed to start${NC}"
    docker-compose ps
    exit 1
fi

cd ..

# Display access URLs
echo
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}Web Applications (Direct Access - No WAF Logging)${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo -e "  DVWA:       ${GREEN}http://localhost:8081${NC} (admin/password)"
echo -e "  Juice Shop: ${GREEN}http://localhost:3000${NC}"
echo -e "  WebGoat:    ${GREEN}http://localhost:8082/WebGoat/login${NC}"
echo
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}Via Nginx Proxy (WITH WAF Logging - Use these for testing)${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo -e "  DVWA:       ${GREEN}http://localhost:8080${NC}"
echo -e "  Juice Shop: ${GREEN}http://localhost:8090${NC}"
echo -e "  WebGoat:    ${GREEN}http://localhost:8091/WebGoat/login${NC}"
echo
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"

# Ask if user wants to start monitoring
echo
echo -e "${YELLOW}Do you want to start real-time WAF monitoring now?${NC}"
read -p "Start monitoring? (y/n) " -n 1 -r
echo

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo
    echo -e "${BLUE}Starting real-time WAF monitor...${NC}"
    echo -e "${YELLOW}Press Ctrl+C to stop monitoring${NC}"
    echo
    
    # Activate virtual environment if it exists
    if [ -d "wafenv" ]; then
        source wafenv/bin/activate
    fi
    
    # Check for calibration data (use converted format)
    CALIBRATION_DATA="data/parsed/calibration_data.json"
    
    # Convert if needed
    if [ ! -f "$CALIBRATION_DATA" ] && [ -f "data/parsed/parsed_requests.json" ]; then
        echo -e "${YELLOW}Converting calibration data to detector format...${NC}"
        python3 convert_calibration_data.py
    fi
    
    if [ -f "$CALIBRATION_DATA" ]; then
        echo -e "${GREEN}✓ Using calibration data: $CALIBRATION_DATA${NC}"
        python3 realtime_waf_monitor.py --model "$MODEL_PATH" --logs-dir nginx/logs --calibration "$CALIBRATION_DATA"
    else
        echo -e "${YELLOW}⚠ Warning: No calibration data found. Detection may be less accurate.${NC}"
        python3 realtime_waf_monitor.py --model "$MODEL_PATH" --logs-dir nginx/logs
    fi
else
    echo
    echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}Services are running!${NC}"
    echo
    echo "To start monitoring manually, run:"
    echo -e "  ${YELLOW}python3 realtime_waf_monitor.py --model $MODEL_PATH${NC}"
    echo
    echo "To stop all services:"
    echo -e "  ${YELLOW}./stop_waf_system.sh${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
fi
