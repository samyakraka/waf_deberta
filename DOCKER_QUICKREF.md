# 🐳 Quick Reference: Docker Commands

## Essential Commands

### Start Everything

```bash
# Using Docker Compose
docker-compose up -d

# Or using Make
make up
```

### Stop Everything

```bash
docker-compose down
```

### View Logs

```bash
# All services
docker-compose logs -f

# WAF only
docker-compose logs -f waf

# Tail last 100 lines
docker-compose logs --tail=100 waf
```

### Check Status

```bash
docker-compose ps
```

### Access Container

```bash
# Regular user
docker exec -it waf-application /bin/bash

# As root (for debugging)
docker exec -it -u root waf-application /bin/bash
```

### Restart Services

```bash
docker-compose restart
```

### Rebuild Image

```bash
docker-compose build --no-cache
docker-compose up -d
```

## Testing Commands

### Test WAF UI

```bash
curl http://localhost:5000
```

### Test Benign Request

```bash
curl "http://localhost:5000/test?id=1"
```

### Test SQL Injection

```bash
curl "http://localhost:5000/test?id=1' OR '1'='1"
```

### Test XSS

```bash
curl "http://localhost:5000/test?input=<script>alert(1)</script>"
```

### Test Path Traversal

```bash
curl "http://localhost:5000/test?page=../../../../etc/passwd"
```

## Maintenance Commands

### Clean Up

```bash
# Remove containers
docker-compose down

# Remove containers and images
docker-compose down --rmi all

# Remove everything including volumes
docker-compose down -v --rmi all

# Prune system
docker system prune -af --volumes
```

### Update Images

```bash
docker-compose pull
docker-compose up -d
```

### Check Resources

```bash
docker stats
```

### Check Health

```bash
# WAF health
curl -f http://localhost:5000/

# Redis health
docker exec waf-redis redis-cli ping
```

## Debugging Commands

### View Container Logs

```bash
docker logs waf-application
docker logs waf-redis
docker logs waf-nginx
```

### Inspect Container

```bash
docker inspect waf-application
```

### Check Environment Variables

```bash
docker exec waf-application env
```

### Check Running Processes

```bash
docker exec waf-application ps aux
```

### Check Network

```bash
docker network inspect waf-network
```

### Test Redis Connection

```bash
docker exec waf-redis redis-cli ping
docker exec waf-redis redis-cli KEYS "*"
```

## Advanced Commands

### Export Container

```bash
docker export waf-application > waf-backup.tar
```

### Copy Files

```bash
# From container to host
docker cp waf-application:/app/data/parsed/new_benign_logs.json ./

# From host to container
docker cp ./config.py waf-application:/app/
```

### Monitor Resources

```bash
docker stats --no-stream waf-application
```

### View Port Mappings

```bash
docker port waf-application
```

## Make Commands (if using Makefile)

```bash
make help           # Show all commands
make build          # Build image
make up             # Start services
make down           # Stop services
make logs           # View logs
make logs-waf       # View WAF logs only
make health         # Check health
make ps             # List containers
make rebuild        # Rebuild and restart
make shell          # Access container
make clean          # Remove everything
make test           # Run tests
make test-attack    # Test attack detection
```

## Service URLs

- **WAF UI**: http://localhost:5000
- **DVWA**: http://localhost:8081
- **Juice Shop**: http://localhost:3000
- **WebGoat**: http://localhost:8082
- **Nginx**: http://localhost:8080
- **Redis**: localhost:6379

## Environment Variables

Set in `docker-compose.yml` or `.env` file:

```bash
REDIS_HOST=redis
REDIS_PORT=6379
FLASK_ENV=production
PYTHONUNBUFFERED=1
```

## Troubleshooting

### Container won't start

```bash
docker-compose logs waf
docker inspect waf-application
```

### Port already in use

```bash
# Find what's using the port
lsof -i :5000

# Or change port in docker-compose.yml
ports:
  - "7000:5000"
```

### Redis connection failed

```bash
# Check Redis is running
docker-compose ps redis

# Test connection
docker exec waf-redis redis-cli ping
```

### Out of memory

```bash
# Check memory usage
docker stats

# Increase memory limit in docker-compose.yml
mem_limit: 6g
```

## Best Practices

1. **Always use `-d` flag** to run in detached mode
2. **Check logs** after starting services
3. **Wait for health checks** before testing
4. **Use `docker-compose`** instead of individual commands
5. **Regular cleanup** to save disk space
6. **Monitor resources** to avoid issues

## Quick Troubleshooting Flow

```bash
# 1. Check if services are running
docker-compose ps

# 2. Check logs for errors
docker-compose logs -f waf

# 3. Check health
curl http://localhost:5000/

# 4. If issues persist, restart
docker-compose restart

# 5. If still broken, rebuild
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

## Additional Resources

- **Full Deployment Guide**: `DOCKER_DEPLOYMENT.md`
- **Security Hardening**: `DOCKER_SECURITY.md`
- **Main README**: `README.md`

---

**Pro Tip**: Use `make` commands for convenience! Run `make help` to see all available commands.
