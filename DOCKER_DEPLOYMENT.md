# 🐳 Docker Deployment Guide for WAF System

## Overview

This guide explains how to deploy the WAF (Web Application Firewall) system using Docker. The system includes:

- **WAF Application**: ML-based detection with 400+ Redis rules
- **Redis**: In-memory rule storage
- **Test Applications**: DVWA, Juice Shop, WebGoat for testing
- **Nginx**: Reverse proxy for log collection

## ⚠️ Important: Data Persistence Behavior

**By design, this Docker setup does NOT persist data after container stops:**

### Data That Will Be Lost When Container Stops:

- ✅ Runtime logs (`data/parsed/new_benign_logs.json`, `new_attack_logs.json`)
- ✅ Training history (`models/deberta-waf/training_history.json`)
- ✅ Incremental stats (`models/deberta-waf/incremental_stats.json`)
- ✅ Redis rules (in-memory only)
- ✅ Nginx access logs
- ✅ Generated reports

### Data That Persists (Built into Image):

- ✅ Base ML model files
- ✅ Static rules configuration
- ✅ Application code
- ✅ Base calibration data

**Why?** This ensures clean state on each deployment and prevents container bloat from accumulated logs.

---

## 🚀 Quick Start

### Prerequisites

- Docker Engine 20.10+
- Docker Compose 1.29+
- At least 4GB RAM available
- 10GB free disk space

### 1. Build the Docker Image

```bash
# Navigate to project directory
cd /Users/samyakraka/Documents/SIH25-WAF/waf_deberta

# Build the WAF image
docker build -t waf-system:latest .
```

**Build time:** ~5-10 minutes (depending on internet speed)

### 2. Deploy with Docker Compose

```bash
# Start all services (WAF + Redis + Test Apps)
docker-compose up -d

# View logs
docker-compose logs -f waf

# Check status
docker-compose ps
```

### 3. Access the System

Once deployed, access:

- **WAF UI**: http://localhost:5000
- **DVWA**: http://localhost:8081
- **Juice Shop**: http://localhost:3000
- **WebGoat**: http://localhost:8082
- **Nginx Proxy**: http://localhost:8080

### 4. Stop and Remove

```bash
# Stop all services
docker-compose down

# Stop and remove volumes (if any)
docker-compose down -v

# Remove images
docker-compose down --rmi all
```

---

## 🔒 Security Features

### 1. Non-Root User

- Application runs as `wafuser` (UID 1000)
- No root privileges inside container

### 2. Security Options

- `no-new-privileges`: Prevents privilege escalation
- Minimal capabilities (only `NET_BIND_SERVICE`)
- All other capabilities dropped

### 3. Network Isolation

- Isolated bridge network for inter-service communication
- Only necessary ports exposed to host

### 4. Redis Security

- No persistence enabled (`--save ""`)
- AOF disabled (`--appendonly no`)
- Data exists only in memory

### 5. Temporary File Systems

- Runtime data stored in `tmpfs` (RAM-based)
- Automatically cleared when container stops
- No data leakage to host filesystem

---

## 📦 Docker Image Details

### Image Size

- Base image: ~450MB
- Final image: ~2-3GB (includes ML models)

### Layers

1. **Base layer**: Python 3.10 + system dependencies
2. **Dependencies**: Python packages (torch, transformers, etc.)
3. **Application**: Code + models
4. **Runtime**: Configuration + user setup

### Optimizations

- Multi-stage build (smaller final image)
- Layer caching for faster rebuilds
- Only required files included via `.dockerignore`

---

## 🔧 Configuration

### Environment Variables

You can customize the deployment using environment variables in `docker-compose.yml`:

```yaml
environment:
  - REDIS_HOST=redis # Redis hostname
  - REDIS_PORT=6379 # Redis port
  - FLASK_ENV=production # Flask environment
  - PYTHONUNBUFFERED=1 # Python logging
```

### Port Mappings

Default port mappings in `docker-compose.yml`:

| Service    | Container Port | Host Port | Purpose       |
| ---------- | -------------- | --------- | ------------- |
| WAF UI     | 5000           | 5000      | Web interface |
| Redis      | 6379           | 6379      | Rule storage  |
| DVWA       | 80             | 8081      | Test app      |
| Juice Shop | 3000           | 3000      | Test app      |
| WebGoat    | 8080           | 8082      | Test app      |
| Nginx      | 80             | 8080      | Reverse proxy |

**To change ports**, edit `docker-compose.yml`:

```yaml
services:
  waf:
    ports:
      - "7000:5000" # Host port 7000 -> Container port 5000
```

---

## 🏗️ Advanced Usage

### Run WAF Only (Without Test Apps)

```bash
# Start only WAF and Redis
docker-compose up -d waf redis
```

### Custom Model Path

Mount your own model from host:

```yaml
services:
  waf:
    volumes:
      - ./my-custom-model:/app/models/deberta-waf/best_model:ro
```

### Persist Data (Optional)

⚠️ **Not recommended** but if you need persistence:

```yaml
services:
  waf:
    volumes:
      - waf-data:/app/data/parsed
      - waf-models:/app/models/deberta-waf

volumes:
  waf-data:
  waf-models:
```

**Remove the `tmpfs` mounts if using volumes!**

### Scale for Production

```yaml
services:
  waf:
    deploy:
      replicas: 3
      resources:
        limits:
          cpus: "2"
          memory: 4G
        reservations:
          cpus: "1"
          memory: 2G
```

---

## 🔍 Monitoring & Logs

### View Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f waf

# Last 100 lines
docker-compose logs --tail=100 waf
```

### Health Checks

All services have health checks:

```bash
# Check health status
docker-compose ps

# Inspect health
docker inspect waf-application | grep -A 10 Health
```

### Access Container Shell

```bash
# Execute shell in running container
docker exec -it waf-application /bin/bash

# As root (for debugging)
docker exec -it -u root waf-application /bin/bash
```

---

## 🐛 Troubleshooting

### Problem: Container won't start

**Check logs:**

```bash
docker-compose logs waf
```

**Common issues:**

- Redis not ready: Wait for health check
- Port conflict: Change port in `docker-compose.yml`
- OOM: Increase Docker memory limit

### Problem: Redis connection failed

**Verify Redis:**

```bash
docker-compose ps redis
docker-compose logs redis
```

**Test connection:**

```bash
docker exec -it waf-redis redis-cli ping
# Should return: PONG
```

### Problem: Model not found

**Check model files:**

```bash
docker exec -it waf-application ls -la /app/models/deberta-waf/
```

**Rebuild image if needed:**

```bash
docker-compose build --no-cache waf
```

### Problem: Permission denied errors

**Check user permissions:**

```bash
docker exec -it waf-application id
# Should show: uid=1000(wafuser) gid=1000(wafuser)
```

**Fix ownership (rebuild with):**

```dockerfile
RUN chown -R wafuser:wafuser /app
```

---

## 📊 Performance Tuning

### Memory Limits

Recommended resources:

- **WAF**: 2-4GB RAM
- **Redis**: 256-512MB RAM
- **Test Apps**: 512MB each

Set in `docker-compose.yml`:

```yaml
services:
  waf:
    mem_limit: 4g
    mem_reservation: 2g
```

### CPU Limits

```yaml
services:
  waf:
    cpus: 2.0
```

### Disable Test Apps

If not needed:

```yaml
# Comment out or remove
# dvwa:
# juiceshop:
# webgoat:
# nginx:
```

---

## 🔐 Production Deployment

### Best Practices

1. **Use secrets for credentials:**

   ```yaml
   secrets:
     admin_password:
       file: ./secrets/admin_password.txt
   ```

2. **Enable TLS/SSL:**

   - Use reverse proxy (Nginx/Traefik) with Let's Encrypt
   - Terminate SSL before WAF

3. **Use Docker Swarm or Kubernetes:**

   - High availability
   - Load balancing
   - Auto-scaling

4. **Monitor resources:**

   - Prometheus + Grafana
   - Docker stats
   - Application metrics

5. **Regular updates:**
   ```bash
   docker-compose pull
   docker-compose up -d
   ```

### Docker Swarm Example

```bash
# Initialize swarm
docker swarm init

# Deploy stack
docker stack deploy -c docker-compose.yml waf-stack

# Scale service
docker service scale waf-stack_waf=3

# Update service
docker service update --image waf-system:v2 waf-stack_waf
```

---

## 📝 Maintenance

### Cleanup

```bash
# Remove stopped containers
docker container prune

# Remove unused images
docker image prune -a

# Remove unused volumes
docker volume prune

# Remove everything
docker system prune -a --volumes
```

### Backup (if using volumes)

```bash
# Backup volume
docker run --rm -v waf-data:/data -v $(pwd):/backup \
  alpine tar czf /backup/waf-data-backup.tar.gz /data

# Restore volume
docker run --rm -v waf-data:/data -v $(pwd):/backup \
  alpine tar xzf /backup/waf-data-backup.tar.gz -C /
```

### Update Strategy

1. Pull latest code
2. Rebuild image: `docker-compose build`
3. Stop old containers: `docker-compose down`
4. Start new containers: `docker-compose up -d`
5. Verify: `docker-compose logs -f`

---

## 🎯 Testing the Deployment

### 1. Test WAF UI

```bash
curl http://localhost:5000
# Should return HTML page
```

### 2. Test Attack Detection

```bash
# Benign request
curl "http://localhost:5000/test?id=1"

# SQL Injection (should be blocked)
curl "http://localhost:5000/test?id=1' OR '1'='1"
```

### 3. Test Redis Connection

```bash
# Check rules loaded
docker exec -it waf-redis redis-cli KEYS "*"
```

### 4. Test Log Monitoring

1. Open WAF UI: http://localhost:5000
2. Navigate to "Log Monitoring" tab
3. Click "Start Monitoring"
4. Generate traffic to test apps
5. See real-time detections

---

## 📚 Additional Resources

- **Docker Documentation**: https://docs.docker.com
- **Docker Compose Reference**: https://docs.docker.com/compose
- **Docker Security**: https://docs.docker.com/engine/security
- **WAF Project README**: See `README.md`

---

## 🆘 Support

For issues or questions:

1. Check logs: `docker-compose logs -f waf`
2. Verify health: `docker-compose ps`
3. Check GitHub issues
4. Contact ISRO WAF Team

---

## 📄 License

See project LICENSE file for details.

---

**Last Updated**: December 2024  
**Version**: 1.0.0  
**Author**: ISRO WAF Team
