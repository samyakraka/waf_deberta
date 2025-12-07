# 🐳 Docker Deployment - Getting Started

## 🚀 Quick Start (3 Steps)

### Step 1: Clone/Navigate to Project

```bash
cd /Users/samyakraka/Documents/SIH25-WAF/waf_deberta
```

### Step 2: Run Quick Start Script

```bash
chmod +x docker-quickstart.sh  # Make executable (first time only)
./docker-quickstart.sh         # Automated setup
```

### Step 3: Access WAF UI

Open in browser: **http://localhost:5000**

---

## 📋 What You Get

After deployment:

| Service        | URL                   | Description             |
| -------------- | --------------------- | ----------------------- |
| **WAF UI**     | http://localhost:5000 | Main web interface      |
| **DVWA**       | http://localhost:8081 | Test vulnerable app     |
| **Juice Shop** | http://localhost:3000 | OWASP test app          |
| **WebGoat**    | http://localhost:8082 | OWASP learning platform |
| **Nginx**      | http://localhost:8080 | Reverse proxy           |

---

## 🔧 Alternative Deployment Methods

### Method 1: Using Make (Recommended)

```bash
make build    # Build Docker image
make up       # Start all services
make logs     # View logs
make test     # Run tests
```

### Method 2: Using Docker Compose

```bash
docker-compose build        # Build image
docker-compose up -d        # Start services
docker-compose logs -f waf  # View logs
docker-compose ps           # Check status
```

### Method 3: Manual Docker Commands

```bash
# Build image
docker build -t waf-system:latest .

# Create network
docker network create waf-network

# Start Redis
docker run -d --name waf-redis --network waf-network redis:7-alpine

# Start WAF
docker run -d --name waf-application \
  --network waf-network \
  -p 5000:5000 \
  -e REDIS_HOST=waf-redis \
  waf-system:latest
```

---

## ⚙️ Prerequisites

- **Docker Engine**: 20.10+ ([Install Docker](https://docs.docker.com/get-docker/))
- **Docker Compose**: 1.29+ ([Install Compose](https://docs.docker.com/compose/install/))
- **System Resources**:
  - 4GB RAM minimum (8GB recommended)
  - 10GB free disk space
  - 2+ CPU cores

### Verify Prerequisites

```bash
docker --version          # Should show Docker 20.10+
docker-compose --version  # Should show 1.29+
docker info              # Check if daemon is running
```

---

## 🧪 Testing the Deployment

### Test 1: WAF UI Access

```bash
curl http://localhost:5000
# Should return HTML page
```

### Test 2: Benign Request

```bash
curl "http://localhost:5000/test?id=1"
# Should be allowed
```

### Test 3: SQL Injection

```bash
curl "http://localhost:5000/test?id=1' OR '1'='1"
# Should be BLOCKED
```

### Test 4: XSS Attack

```bash
curl "http://localhost:5000/test?input=<script>alert(1)</script>"
# Should be BLOCKED
```

### Test 5: Path Traversal

```bash
curl "http://localhost:5000/test?page=../../../../etc/passwd"
# Should be BLOCKED
```

### Run All Tests

```bash
make test         # Basic tests
make test-attack  # Attack detection tests
```

---

## 📊 Monitoring & Logs

### View Logs

```bash
# All services
docker-compose logs -f

# WAF only
docker-compose logs -f waf

# Last 100 lines
docker-compose logs --tail=100 waf

# Real-time with timestamps
docker-compose logs -f -t waf
```

### Check Status

```bash
# List containers
docker-compose ps

# Check health
make health

# Resource usage
docker stats
```

### Access Container

```bash
# Regular shell
docker exec -it waf-application /bin/bash

# Root shell (for debugging)
docker exec -it -u root waf-application /bin/bash
```

---

## 🛑 Stopping & Cleaning Up

### Stop Services

```bash
# Graceful stop
docker-compose down

# Or using Make
make down
```

### Remove Everything

```bash
# Remove containers and images
docker-compose down --rmi all

# Remove everything including volumes
docker-compose down -v --rmi all

# Or using Make
make clean
```

### Prune Docker System

```bash
# Clean up unused resources
docker system prune -af --volumes

# Or using Make
make prune
```

---

## 🔄 Updating & Restarting

### Restart Services

```bash
docker-compose restart
# Or: make restart
```

### Rebuild & Restart

```bash
docker-compose down
docker-compose build --no-cache
docker-compose up -d
# Or: make rebuild
```

### Update Images

```bash
docker-compose pull
docker-compose up -d
# Or: make update
```

---

## 💾 Data Persistence Behavior

### ⚠️ Important: Data is NOT Persistent

**By design, runtime data is stored in tmpfs (RAM) and will be lost when container stops:**

#### What Gets Lost ❌

- `data/parsed/new_benign_logs.json` - Runtime benign logs
- `data/parsed/new_attack_logs.json` - Runtime attack logs
- `models/deberta-waf/training_history.json` - Training history
- `models/deberta-waf/incremental_stats.json` - Incremental stats
- `nginx/logs/*.log` - Access logs
- Redis data - All rules and cache

#### What Persists ✅

- Base ML model (built into image)
- Static rules configuration
- Application code
- Base calibration data

**Why?**

1. Clean state on each deployment
2. No container bloat
3. Enhanced security (no sensitive data persists)
4. Easy scaling and portability

### Optional: Enable Persistence

If you **really** need persistence, edit `docker-compose.yml`:

```yaml
services:
  waf:
    volumes:
      - waf-data:/app/data/parsed
      - waf-models:/app/models/deberta-waf
    # Remove tmpfs mounts

volumes:
  waf-data:
  waf-models:
```

---

## 🔒 Security Features

### Built-in Security ✅

- **Non-root user**: Runs as `wafuser` (UID 1000)
- **Minimal capabilities**: Only `NET_BIND_SERVICE`
- **No privilege escalation**: `no-new-privileges:true`
- **Tmpfs storage**: Runtime data in RAM
- **Redis no-persistence**: In-memory only
- **Network isolation**: Isolated bridge network
- **Health checks**: Automatic monitoring

### Additional Hardening

See **`DOCKER_SECURITY.md`** for:

- TLS/SSL encryption
- Resource limits
- Secrets management
- Image scanning
- Runtime monitoring
- Compliance guidelines

---

## 🐛 Troubleshooting

### Problem: Container won't start

```bash
# Check logs
docker-compose logs waf

# Inspect container
docker inspect waf-application

# Common causes:
# - Redis not ready (wait a few seconds)
# - Port conflict (change port in docker-compose.yml)
# - Insufficient memory (check docker stats)
```

### Problem: Redis connection failed

```bash
# Check Redis status
docker-compose ps redis

# Test Redis
docker exec waf-redis redis-cli ping
# Should return: PONG

# Restart Redis
docker-compose restart redis
```

### Problem: Port already in use

```bash
# Find what's using the port
lsof -i :5000

# Kill the process or change port in docker-compose.yml
ports:
  - "7000:5000"  # Use port 7000 instead
```

### Problem: Out of memory

```bash
# Check memory usage
docker stats

# Increase Docker memory limit (Docker Desktop)
# Settings → Resources → Memory → Increase to 6GB+

# Or set in docker-compose.yml
mem_limit: 6g
```

### Problem: Image build fails

```bash
# Clean build cache
docker builder prune -af

# Rebuild from scratch
docker-compose build --no-cache
```

### Quick Fix for Most Issues

```bash
# Stop everything
docker-compose down

# Clean up
docker system prune -f

# Rebuild and restart
docker-compose build --no-cache
docker-compose up -d

# Check logs
docker-compose logs -f waf
```

---

## 📚 Documentation

### Complete Guides

1. **DOCKER_SUMMARY.md** (10 pages)

   - Overview and quick reference
   - Architecture diagram
   - Best practices

2. **DOCKER_DEPLOYMENT.md** (40 pages)

   - Complete deployment guide
   - Configuration options
   - Production deployment
   - Performance tuning
   - Advanced usage

3. **DOCKER_SECURITY.md** (30 pages)

   - Security features
   - Hardening recommendations
   - Compliance guidelines
   - Monitoring & alerting
   - Incident response

4. **DOCKER_QUICKREF.md** (5 pages)

   - Quick command reference
   - Common tasks
   - Troubleshooting tips

5. **DOCKER_ARCHITECTURE.txt**
   - Visual architecture diagram
   - Component overview
   - Data flow

### Quick Command Reference

```bash
# Build & Deploy
make build          # Build image
make up             # Start services
make down           # Stop services
make rebuild        # Rebuild and restart

# Monitoring
make logs           # View all logs
make logs-waf       # View WAF logs
make health         # Check health
make ps             # List containers

# Testing
make test           # Run basic tests
make test-attack    # Test attack detection

# Maintenance
make clean          # Remove everything
make prune          # Clean Docker system
make shell          # Access container

# Help
make help           # Show all commands
```

---

## 🎯 Use Cases

### Development

```bash
make build
make up
# Develop and test
make down
```

### Testing

```bash
make up
make test
make test-attack
# Review logs
make logs-waf
```

### Production (Basic)

```bash
# Build and start
docker-compose build
docker-compose up -d

# Monitor
docker-compose logs -f waf

# Scale (if needed)
docker-compose up -d --scale waf=3
```

### Production (Advanced)

See **`DOCKER_DEPLOYMENT.md`** for:

- TLS/SSL setup
- Load balancing
- High availability
- Kubernetes deployment
- CI/CD integration

---

## 🆘 Getting Help

### Check Documentation

1. Read **DOCKER_SUMMARY.md** first
2. Check **DOCKER_DEPLOYMENT.md** for detailed guide
3. Review **DOCKER_SECURITY.md** for security
4. Use **DOCKER_QUICKREF.md** for quick commands

### Debug Steps

1. Check logs: `docker-compose logs -f waf`
2. Verify health: `make health`
3. Check resources: `docker stats`
4. Inspect container: `docker inspect waf-application`
5. Access shell: `docker exec -it waf-application /bin/bash`

### Common Commands

```bash
# Is Docker running?
docker info

# Are services up?
docker-compose ps

# What's in the logs?
docker-compose logs --tail=50 waf

# What's using resources?
docker stats --no-stream

# What's on the network?
docker network inspect waf-network
```

---

## ✅ Success Checklist

After deployment, verify:

- [ ] Docker and Docker Compose are installed
- [ ] All services are running: `docker-compose ps`
- [ ] WAF UI is accessible: `curl http://localhost:5000`
- [ ] Redis is connected: `docker exec waf-redis redis-cli ping`
- [ ] Health checks are passing
- [ ] No errors in logs: `docker-compose logs waf`
- [ ] Benign requests work
- [ ] Attack detection works
- [ ] Test apps are accessible

---

## 🎉 You're All Set!

Your WAF system is now running in Docker with:

✅ **Complete isolation** - All services in containers  
✅ **Secure by default** - Non-root, minimal capabilities  
✅ **Easy management** - One-command deployment  
✅ **Production-ready** - Health checks, monitoring  
✅ **Well-documented** - 85+ pages of guides  
✅ **Non-persistent** - Clean state on restart

**Next Steps:**

1. Open http://localhost:5000
2. Try example attack payloads
3. Monitor live detection
4. Read advanced documentation

**Happy Testing! 🚀**

---

## 📞 Support

- **Documentation**: See `DOCKER_*.md` files
- **Commands**: Run `make help`
- **Issues**: Check logs with `docker-compose logs -f waf`

---

**Created**: December 2024  
**Version**: 1.0.0  
**Author**: GitHub Copilot for ISRO WAF Team
