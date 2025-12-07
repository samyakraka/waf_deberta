# Makefile for WAF Docker Deployment
# Convenient commands for building, running, and managing the WAF system

.PHONY: help build up down logs clean test health rebuild shell

# Default target
help:
	@echo "🛡️  WAF Docker Deployment Commands"
	@echo ""
	@echo "Build & Deploy:"
	@echo "  make build       - Build Docker image"
	@echo "  make up          - Start all services"
	@echo "  make down        - Stop all services"
	@echo "  make rebuild     - Rebuild and restart"
	@echo ""
	@echo "Monitoring:"
	@echo "  make logs        - View all logs (follow mode)"
	@echo "  make logs-waf    - View WAF logs only"
	@echo "  make health      - Check service health"
	@echo "  make ps          - List running containers"
	@echo ""
	@echo "Maintenance:"
	@echo "  make clean       - Remove containers and images"
	@echo "  make prune       - Clean up Docker system"
	@echo "  make shell       - Access WAF container shell"
	@echo ""
	@echo "Testing:"
	@echo "  make test        - Run basic tests"
	@echo "  make test-attack - Test with attack payloads"
	@echo ""

# Build Docker image
build:
	@echo "🔨 Building WAF Docker image..."
	docker-compose build

# Start all services
up:
	@echo "🚀 Starting WAF system..."
	docker-compose up -d
	@echo "✅ Services started!"
	@echo "   WAF UI:      http://localhost:5001"
	@echo "   DVWA:        http://localhost:8081"
	@echo "   Juice Shop:  http://localhost:3000"
	@echo "   WebGoat:     http://localhost:8082"
	@make health

# Stop all services
down:
	@echo "🛑 Stopping WAF system..."
	docker-compose down

# View all logs (follow mode)
logs:
	docker-compose logs -f

# View WAF logs only
logs-waf:
	docker-compose logs -f waf

# Check service health
health:
	@echo "🏥 Checking service health..."
	@docker-compose ps
	@echo ""
	@echo "Redis health:"
	@docker exec -it waf-redis redis-cli ping || echo "Redis not responding"
	@echo ""
	@echo "WAF health:"
	@curl -f http://localhost:5001/ > /dev/null 2>&1 && echo "✅ WAF is healthy" || echo "❌ WAF is not responding"

# List running containers
ps:
	docker-compose ps

# Rebuild and restart
rebuild:
	@echo "🔄 Rebuilding and restarting..."
	@make down
	@make build
	@make up

# Access WAF container shell
shell:
	@echo "🐚 Accessing WAF container..."
	docker exec -it waf-application /bin/bash

# Access as root (for debugging)
shell-root:
	@echo "🐚 Accessing WAF container as root..."
	docker exec -it -u root waf-application /bin/bash

# Remove containers and images
clean:
	@echo "🧹 Cleaning up..."
	docker-compose down --rmi all -v
	@echo "✅ Cleanup complete"

# Prune Docker system
prune:
	@echo "🗑️  Pruning Docker system..."
	docker system prune -af --volumes
	@echo "✅ Prune complete"

# Basic tests
test:
	@echo "🧪 Running basic tests..."
	@echo "1. Testing WAF UI..."
	@curl -f http://localhost:5001/ > /dev/null && echo "✅ WAF UI is accessible" || echo "❌ WAF UI failed"
	@echo ""
	@echo "2. Testing Redis..."
	@docker exec waf-redis redis-cli ping && echo "✅ Redis is working" || echo "❌ Redis failed"
	@echo ""
	@echo "3. Testing benign request..."
	@curl -s "http://localhost:5001/api/test-curl" \
		-H "Content-Type: application/json" \
		-d '{"curl_command": "curl \"http://localhost:8080/test?id=1\""}' | grep -q "benign" && \
		echo "✅ Benign request test passed" || echo "❌ Benign request test failed"

# Test with attack payloads
test-attack:
	@echo "🚨 Testing attack detection..."
	@echo "1. SQL Injection test..."
	@curl -s "http://localhost:5001/api/test-curl" \
		-H "Content-Type: application/json" \
		-d '{"curl_command": "curl \"http://localhost:8080/test?id=1'\'' OR '\''1'\''='\''1\""}' | grep -q "malicious" && \
		echo "✅ SQL Injection detected" || echo "❌ SQL Injection not detected"
	@echo ""
	@echo "2. XSS test..."
	@curl -s "http://localhost:5000/api/test-curl" \
		-H "Content-Type: application/json" \
		-d '{"curl_command": "curl \"http://localhost:8080/test?input=<script>alert(1)</script>\""}' | grep -q "malicious" && \
		echo "✅ XSS detected" || echo "❌ XSS not detected"
	@echo ""
	@echo "3. Path Traversal test..."
	@curl -s "http://localhost:5000/api/test-curl" \
		-H "Content-Type: application/json" \
		-d '{"curl_command": "curl \"http://localhost:8080/test?page=../../../../etc/passwd\""}' | grep -q "malicious" && \
		echo "✅ Path Traversal detected" || echo "❌ Path Traversal not detected"

# Backup (if volumes are used)
backup:
	@echo "💾 Creating backup..."
	@mkdir -p backups
	@docker run --rm -v waf-data:/data -v $(PWD)/backups:/backup \
		alpine tar czf /backup/waf-data-$(shell date +%Y%m%d-%H%M%S).tar.gz /data 2>/dev/null || \
		echo "No volumes to backup (this is expected if using tmpfs)"
	@echo "✅ Backup complete"

# View resource usage
stats:
	@echo "📊 Resource usage:"
	docker stats --no-stream

# Quick restart
restart:
	@echo "🔄 Restarting services..."
	docker-compose restart
	@echo "✅ Services restarted"

# Update images
update:
	@echo "🔄 Pulling latest images..."
	docker-compose pull
	@echo "✅ Images updated"

# Initialize Redis rules
init-redis:
	@echo "📦 Initializing Redis rules..."
	docker exec -it waf-application python init_redis_rules.py
	@echo "✅ Redis rules initialized"
