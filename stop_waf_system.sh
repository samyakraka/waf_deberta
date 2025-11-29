#!/bin/bash
# Stop WAF Real-Time Monitoring System

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║          Stopping WAF Monitoring System                       ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo

# Stop monitoring process if running
if pgrep -f "realtime_waf_monitor.py" > /dev/null; then
    echo -e "${YELLOW}Stopping WAF monitor...${NC}"
    pkill -f "realtime_waf_monitor.py"
    echo -e "${GREEN}✓ Monitor stopped${NC}"
fi

# Stop Docker containers
echo -e "${YELLOW}Stopping Docker containers...${NC}"
cd docker
docker-compose down

echo
echo -e "${GREEN}✓ All services stopped${NC}"
echo
echo "To start again, run:"
echo -e "  ${YELLOW}./start_waf_system.sh${NC}"
