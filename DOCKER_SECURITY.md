# 🔒 Docker Security Hardening Guide

## Overview

This guide provides security best practices and hardening recommendations for deploying the WAF system in production environments.

## Security Features Already Implemented

### ✅ 1. Non-Root User

- Container runs as `wafuser` (UID 1000, GID 1000)
- No root privileges inside container
- Prevents privilege escalation attacks

### ✅ 2. Minimal Capabilities

```yaml
cap_drop:
  - ALL
cap_add:
  - NET_BIND_SERVICE
```

- All Linux capabilities dropped by default
- Only bind to privileged ports allowed (if needed)

### ✅ 3. No New Privileges

```yaml
security_opt:
  - no-new-privileges:true
```

- Prevents SUID binaries from gaining additional privileges
- Blocks setuid/setgid bit exploitation

### ✅ 4. Tmpfs for Volatile Data

```yaml
tmpfs:
  - /app/data/parsed:uid=1000,gid=1000,mode=1777
  - /app/logs:uid=1000,gid=1000,mode=1777
  - /tmp
```

- Runtime data stored in RAM (tmpfs)
- Automatically cleared when container stops
- No sensitive data persists on disk

### ✅ 5. Redis Security

```bash
redis-server --save "" --appendonly no
```

- No persistence (in-memory only)
- No data written to disk
- Reduces attack surface

### ✅ 6. Network Isolation

- Isolated bridge network for inter-service communication
- Services not exposed to default bridge network
- Controlled port exposure

### ✅ 7. Health Checks

- Automatic health monitoring
- Fails fast on service issues
- Prevents serving requests when unhealthy

### ✅ 8. Multi-Stage Build

- Smaller attack surface
- Only production dependencies in final image
- Build tools not included in runtime

---

## Additional Production Hardening

### 1. Enable Read-Only Filesystem

For maximum security, enable read-only root filesystem:

```yaml
services:
  waf:
    read_only: true
    tmpfs:
      - /tmp
      - /app/data/parsed
      - /app/logs
      - /app/models/deberta-waf/epoch_2:uid=1000,gid=1000
      - /app/models/deberta-waf/epoch_4:uid=1000,gid=1000
```

**Note:** Some paths need write access for model training.

### 2. Resource Limits

Prevent DoS attacks via resource exhaustion:

```yaml
services:
  waf:
    deploy:
      resources:
        limits:
          cpus: "2"
          memory: 4G
          pids: 100
        reservations:
          cpus: "1"
          memory: 2G

    # Alternative syntax for Docker Compose v2
    mem_limit: 4g
    memswap_limit: 4g
    mem_reservation: 2g
    cpus: 2.0
    pids_limit: 100
```

### 3. AppArmor Profile

Create AppArmor profile for additional MAC (Mandatory Access Control):

```yaml
services:
  waf:
    security_opt:
      - apparmor=docker-default
      - no-new-privileges:true
```

**Custom profile** (`/etc/apparmor.d/docker-waf`):

```
#include <tunables/global>

profile docker-waf flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

  # Allow network access
  network inet tcp,
  network inet udp,

  # Allow read access to app files
  /app/** r,

  # Allow write to specific paths
  /app/data/parsed/** rw,
  /app/logs/** rw,
  /tmp/** rw,

  # Deny everything else
  deny /** w,
}
```

### 4. Seccomp Profile

Limit system calls with seccomp:

```yaml
services:
  waf:
    security_opt:
      - seccomp=/path/to/seccomp-profile.json
```

**Example profile** (`seccomp-profile.json`):

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_ARM64"],
  "syscalls": [
    {
      "names": [
        "accept",
        "accept4",
        "bind",
        "brk",
        "clone",
        "close",
        "connect",
        "dup",
        "dup2",
        "epoll_create",
        "epoll_ctl",
        "epoll_wait",
        "execve",
        "exit",
        "exit_group",
        "fcntl",
        "fstat",
        "futex",
        "getcwd",
        "getdents",
        "getpid",
        "getsockname",
        "getsockopt",
        "listen",
        "lseek",
        "mmap",
        "mprotect",
        "munmap",
        "open",
        "openat",
        "poll",
        "read",
        "recvfrom",
        "rt_sigaction",
        "rt_sigprocmask",
        "sendto",
        "setsockopt",
        "socket",
        "stat",
        "write"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

### 5. User Namespace Remapping

Enable user namespace for additional isolation:

**In Docker daemon config** (`/etc/docker/daemon.json`):

```json
{
  "userns-remap": "default"
}
```

**Restart Docker:**

```bash
sudo systemctl restart docker
```

### 6. Secrets Management

Never hardcode secrets in images or compose files.

**Use Docker Secrets:**

```yaml
secrets:
  admin_password:
    file: ./secrets/admin_password.txt
  redis_password:
    file: ./secrets/redis_password.txt

services:
  waf:
    secrets:
      - admin_password
    environment:
      - ADMIN_PASSWORD_FILE=/run/secrets/admin_password

  redis:
    secrets:
      - redis_password
    command: >
      sh -c '
        export REDIS_PASSWORD=$$(cat /run/secrets/redis_password)
        redis-server --requirepass $$REDIS_PASSWORD
      '
```

**Create secrets directory:**

```bash
mkdir -p secrets
chmod 700 secrets
echo "your-secure-password" > secrets/admin_password.txt
chmod 600 secrets/admin_password.txt
```

### 7. TLS/SSL Encryption

**Option A: Use Nginx reverse proxy with SSL**

```yaml
services:
  nginx-ssl:
    image: nginx:alpine
    ports:
      - "443:443"
    volumes:
      - ./nginx/ssl.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/certs:ro
    depends_on:
      - waf
```

**nginx/ssl.conf:**

```nginx
server {
    listen 443 ssl http2;
    server_name waf.example.com;

    ssl_certificate /etc/nginx/certs/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://waf:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

**Option B: Traefik with Let's Encrypt**

```yaml
services:
  traefik:
    image: traefik:v2.10
    command:
      - "--providers.docker=true"
      - "--entrypoints.websecure.address=:443"
      - "--certificatesresolvers.myresolver.acme.tlschallenge=true"
      - "--certificatesresolvers.myresolver.acme.email=admin@example.com"
      - "--certificatesresolvers.myresolver.acme.storage=/letsencrypt/acme.json"
    ports:
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./letsencrypt:/letsencrypt

  waf:
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.waf.rule=Host(`waf.example.com`)"
      - "traefik.http.routers.waf.entrypoints=websecure"
      - "traefik.http.routers.waf.tls.certresolver=myresolver"
```

### 8. Image Scanning

Scan images for vulnerabilities:

```bash
# Using Trivy
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image waf-system:latest

# Using Snyk
snyk container test waf-system:latest

# Using Docker Scout (built-in)
docker scout cves waf-system:latest
```

### 9. Runtime Security Monitoring

**Falco for runtime detection:**

```yaml
services:
  falco:
    image: falcosecurity/falco:latest
    privileged: true
    volumes:
      - /var/run/docker.sock:/host/var/run/docker.sock
      - /dev:/host/dev
      - /proc:/host/proc:ro
    environment:
      - SKIP_DRIVER_LOADER=true
```

### 10. Audit Logging

Enable Docker audit logging:

```json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3",
    "labels": "production_status",
    "env": "os,customer"
  },
  "audit-log": {
    "enabled": true,
    "log-file": "/var/log/docker/audit.log",
    "max-size": "100m",
    "max-files": 5
  }
}
```

---

## Network Security

### 1. Internal Network Only

```yaml
networks:
  waf-network:
    driver: bridge
    internal: true # No external access

  public-network:
    driver: bridge

services:
  waf:
    networks:
      - waf-network

  nginx:
    networks:
      - waf-network
      - public-network
    ports:
      - "443:443"
```

### 2. Network Policies (Docker Swarm)

```yaml
services:
  waf:
    deploy:
      endpoint_mode: dnsrr
    networks:
      waf-network:
        aliases:
          - waf-backend
```

### 3. Firewall Rules

**Using UFW (Ubuntu):**

```bash
# Allow only necessary ports
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 443/tcp  # HTTPS
sudo ufw allow 22/tcp   # SSH
sudo ufw enable
```

**Using iptables:**

```bash
# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow HTTPS
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Drop everything else
iptables -P INPUT DROP
```

---

## Container Security Scanning

### Pre-deployment Checklist

- [ ] Image scanned for CVEs
- [ ] No hardcoded secrets
- [ ] Running as non-root user
- [ ] Read-only filesystem (where possible)
- [ ] Resource limits configured
- [ ] Health checks implemented
- [ ] Network isolated
- [ ] Logging configured
- [ ] TLS/SSL enabled
- [ ] Secrets externalized

### Automated Scanning Pipeline

```yaml
# .github/workflows/security.yml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Build image
        run: docker build -t waf-system:test .

      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: "waf-system:test"
          format: "sarif"
          output: "trivy-results.sarif"

      - name: Upload to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: "trivy-results.sarif"
```

---

## Compliance & Standards

### CIS Docker Benchmark

Follow CIS Docker Benchmark recommendations:

1. **Host Configuration**

   - Separate partition for containers
   - Use Docker CE/EE from official repo
   - Harden Docker daemon config

2. **Docker Daemon Configuration**

   - Enable content trust
   - Restrict network traffic
   - Enable user namespace
   - Use TLS for daemon socket

3. **Docker Files**

   - Use trusted base images
   - Don't install unnecessary packages
   - Scan images before deployment

4. **Container Runtime**
   - Run as non-root (✅ implemented)
   - Drop unnecessary capabilities (✅ implemented)
   - Mount filesystem read-only (✅ optional)
   - Limit resources (✅ recommended)

### NIST Guidelines

Align with NIST Cybersecurity Framework:

- **Identify**: Know what's in your containers
- **Protect**: Implement security controls
- **Detect**: Monitor for anomalies
- **Respond**: Have incident response plan
- **Recover**: Backup and recovery procedures

---

## Monitoring & Alerting

### Prometheus + Grafana

```yaml
services:
  prometheus:
    image: prom/prometheus
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
    command:
      - "--config.file=/etc/prometheus/prometheus.yml"
    ports:
      - "9090:9090"

  grafana:
    image: grafana/grafana
    ports:
      - "3001:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=secure_password
    volumes:
      - grafana-storage:/var/lib/grafana

volumes:
  grafana-storage:
```

### Alert Rules

```yaml
# prometheus-alerts.yml
groups:
  - name: docker
    interval: 30s
    rules:
      - alert: HighMemoryUsage
        expr: container_memory_usage_bytes{name="waf-application"} > 3e9
        for: 5m
        annotations:
          summary: "High memory usage in WAF container"

      - alert: ContainerDown
        expr: up{job="docker"} == 0
        for: 1m
        annotations:
          summary: "Container is down"
```

---

## Backup & Disaster Recovery

### Backup Strategy (if using volumes)

```bash
#!/bin/bash
# backup.sh

BACKUP_DIR="/backup"
DATE=$(date +%Y%m%d-%H%M%S)

# Backup volumes
docker run --rm \
  -v waf-data:/data \
  -v $BACKUP_DIR:/backup \
  alpine \
  tar czf /backup/waf-data-$DATE.tar.gz /data

# Backup configurations
tar czf $BACKUP_DIR/waf-config-$DATE.tar.gz \
  docker-compose.yml \
  .env \
  nginx/

# Keep only last 7 backups
find $BACKUP_DIR -name "waf-*.tar.gz" -mtime +7 -delete
```

### Disaster Recovery Plan

1. **Regular Backups**: Automated daily backups
2. **Tested Restores**: Monthly restore tests
3. **Documentation**: Keep recovery procedures updated
4. **Redundancy**: Multi-region deployment
5. **Monitoring**: 24/7 alerting

---

## Security Incident Response

### Incident Response Plan

1. **Detection**: Monitor logs and alerts
2. **Containment**: Isolate affected containers
3. **Investigation**: Analyze logs and forensics
4. **Remediation**: Patch and rebuild
5. **Recovery**: Restore from clean backup
6. **Lessons Learned**: Document and improve

### Forensics

```bash
# Capture container state
docker inspect waf-application > investigation/inspect.json

# Export container filesystem
docker export waf-application > investigation/filesystem.tar

# Copy logs
docker logs waf-application > investigation/logs.txt

# Network connections
docker exec waf-application netstat -tunap > investigation/network.txt
```

---

## Summary: Production Deployment Checklist

### Before Deployment

- [ ] Security scan completed
- [ ] Secrets externalized
- [ ] TLS/SSL configured
- [ ] Resource limits set
- [ ] Firewall rules configured
- [ ] Monitoring enabled
- [ ] Backup strategy implemented
- [ ] Incident response plan ready

### After Deployment

- [ ] Health checks passing
- [ ] Logs being collected
- [ ] Alerts configured
- [ ] Performance baseline established
- [ ] Documentation updated
- [ ] Team trained

---

## Additional Resources

- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [NIST Container Security Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf)
- [OWASP Container Security](https://owasp.org/www-project-docker-top-10/)

---

**Last Updated**: December 2024  
**Version**: 1.0.0  
**Author**: ISRO WAF Team
