#!/usr/bin/env bash
# Quick Start Script for WAF Docker Deployment
# Author: ISRO WAF Team

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║       🛡️  WAF Docker Quick Start Script 🛡️              ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check prerequisites
echo -e "${YELLOW}📋 Checking prerequisites...${NC}"

if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker is not installed${NC}"
    echo "Please install Docker: https://docs.docker.com/get-docker/"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}❌ Docker Compose is not installed${NC}"
    echo "Please install Docker Compose: https://docs.docker.com/compose/install/"
    exit 1
fi

echo -e "${GREEN}✅ Docker is installed: $(docker --version)${NC}"
echo -e "${GREEN}✅ Docker Compose is installed: $(docker-compose --version)${NC}"

# Check if Docker daemon is running
if ! docker info &> /dev/null; then
    echo -e "${RED}❌ Docker daemon is not running${NC}"
    echo "Please start Docker Desktop or the Docker daemon"
    exit 1
fi

echo -e "${GREEN}✅ Docker daemon is running${NC}"
echo ""

# Check available resources
echo -e "${YELLOW}💾 Checking system resources...${NC}"
available_memory=$(docker info --format '{{.MemTotal}}' 2>/dev/null || echo "Unknown")
echo -e "Available memory: ${available_memory}"

if [ "$available_memory" != "Unknown" ]; then
    memory_gb=$((available_memory / 1024 / 1024 / 1024))
    if [ $memory_gb -lt 4 ]; then
        echo -e "${YELLOW}⚠️  Warning: Less than 4GB RAM available. Performance may be affected.${NC}"
    else
        echo -e "${GREEN}✅ Sufficient memory available (${memory_gb}GB)${NC}"
    fi
fi
echo ""

# Build image
echo -e "${YELLOW}🔨 Building WAF Docker image...${NC}"
echo "This may take 5-10 minutes on first run..."
if docker-compose build; then
    echo -e "${GREEN}✅ Image built successfully${NC}"
else
    echo -e "${RED}❌ Build failed${NC}"
    exit 1
fi
echo ""

# Start services
echo -e "${YELLOW}🚀 Starting WAF services...${NC}"
if docker-compose up -d; then
    echo -e "${GREEN}✅ Services started successfully${NC}"
else
    echo -e "${RED}❌ Failed to start services${NC}"
    exit 1
fi
echo ""

# Wait for services to be healthy
echo -e "${YELLOW}⏳ Waiting for services to be ready...${NC}"
sleep 5

# Check Redis
echo -n "Checking Redis... "
if docker exec waf-redis redis-cli ping &> /dev/null; then
    echo -e "${GREEN}✅${NC}"
else
    echo -e "${YELLOW}⚠️  Not ready yet${NC}"
fi

# Check WAF
echo -n "Checking WAF... "
max_attempts=30
attempt=0
while [ $attempt -lt $max_attempts ]; do
    if curl -f http://localhost:5000/ &> /dev/null; then
        echo -e "${GREEN}✅${NC}"
        break
    fi
    attempt=$((attempt + 1))
    sleep 2
done

if [ $attempt -eq $max_attempts ]; then
    echo -e "${YELLOW}⚠️  Taking longer than expected${NC}"
    echo -e "${YELLOW}Check logs with: docker-compose logs -f waf${NC}"
fi
echo ""

# Display service URLs
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              🎉 Deployment Complete! 🎉                   ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}Access your services:${NC}"
echo ""
echo -e "  🛡️  ${GREEN}WAF UI:${NC}         http://localhost:5000"
echo -e "  🔴 ${GREEN}DVWA:${NC}           http://localhost:8081"
echo -e "  🧃 ${GREEN}Juice Shop:${NC}     http://localhost:3000"
echo -e "  🐐 ${GREEN}WebGoat:${NC}        http://localhost:8082"
echo -e "  🔧 ${GREEN}Nginx Proxy:${NC}    http://localhost:8080"
echo ""
echo -e "${BLUE}Useful commands:${NC}"
echo ""
echo -e "  View logs:           ${YELLOW}docker-compose logs -f waf${NC}"
echo -e "  Check status:        ${YELLOW}docker-compose ps${NC}"
echo -e "  Stop services:       ${YELLOW}docker-compose down${NC}"
echo -e "  Restart services:    ${YELLOW}docker-compose restart${NC}"
echo -e "  Access container:    ${YELLOW}docker exec -it waf-application /bin/bash${NC}"
echo ""
echo -e "${BLUE}Testing:${NC}"
echo ""
echo -e "  Run tests:           ${YELLOW}make test${NC}"
echo -e "  Test attacks:        ${YELLOW}make test-attack${NC}"
echo ""
echo -e "${YELLOW}📚 For detailed documentation, see: DOCKER_DEPLOYMENT.md${NC}"
echo ""
echo -e "${GREEN}Happy Testing! 🚀${NC}"
