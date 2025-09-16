# Docker Installation Guide

Docker is a free and open-source containerization platform that enables developers to package applications and their dependencies into portable containers. Originally developed by Solomon Hykes at dotCloud, Docker revolutionized application deployment by providing OS-level virtualization. It serves as a FOSS alternative to proprietary virtualization solutions like VMware vSphere, Microsoft Hyper-V containers, or commercial container platforms, offering comparable functionality with features like image layering, container orchestration, and resource isolation.

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Supported Operating Systems](#supported-operating-systems)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Service Management](#service-management)
6. [Troubleshooting](#troubleshooting)
7. [Security Considerations](#security-considerations)
8. [Performance Tuning](#performance-tuning)
9. [Backup and Restore](#backup-and-restore)
10. [System Requirements](#system-requirements)
11. [Support](#support)
12. [Contributing](#contributing)
13. [License](#license)
14. [Acknowledgments](#acknowledgments)
15. [Version History](#version-history)
16. [Appendices](#appendices)

## 1. Prerequisites

- **Hardware Requirements**:
  - CPU: 64-bit processor with virtualization support (Intel VT-x/AMD-V)
  - RAM: 2GB minimum (4GB+ recommended for production)
  - Storage: 20GB minimum (50GB+ recommended, SSD preferred)
  - BIOS: Virtualization must be enabled
- **Operating System**: 
  - Linux: Kernel 3.10+ with cgroups and namespaces support
  - macOS: 10.15+ (Catalina or newer)
  - Windows: Windows 10 64-bit Pro/Enterprise/Education (Build 19041+)
- **Network Requirements**:
  - Internet connection for pulling images
  - Port 2375 (unencrypted) or 2376 (TLS) for Docker API
  - Port 2377 for Swarm mode cluster management
  - Port 7946 TCP/UDP for container network discovery
  - Port 4789 UDP for overlay network traffic
- **Dependencies**:
  - iptables 1.4+ (Linux)
  - Git (for building images)
  - systemd or compatible init system (Linux)
- **System Access**: root or sudo privileges required


## 2. Supported Operating Systems

This guide supports installation on:
- RHEL 8/9 and derivatives (CentOS Stream, Rocky Linux, AlmaLinux)
- Debian 11/12
- Ubuntu 20.04/22.04/24.04 LTS
- Arch Linux (rolling release)
- Alpine Linux 3.18+
- openSUSE Leap 15.5+ / Tumbleweed
- SUSE Linux Enterprise Server (SLES) 15+
- macOS 12+ (Monterey and later) 
- FreeBSD 13+
- Windows 10/11/Server 2019+ (where applicable)

## 3. Installation

### RHEL/CentOS/Rocky Linux/AlmaLinux

```bash
# Remove old versions
sudo yum remove docker \
                docker-client \
                docker-client-latest \
                docker-common \
                docker-latest \
                docker-latest-logrotate \
                docker-logrotate \
                docker-engine

# Install required packages
sudo yum install -y yum-utils

# Add Docker repository
sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo

# Install Docker Engine
sudo yum install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Enable and start Docker
sudo systemctl enable --now docker

# Verify installation
sudo docker run hello-world
```

### Debian/Ubuntu

```bash
# Update package index
sudo apt-get update

# Install prerequisites
sudo apt-get install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release

# Add Docker's official GPG key
sudo mkdir -m 0755 -p /etc/apt/keyrings
wget -O docker.gpg https://download.docker.com/linux/ubuntu/gpg
sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg < docker.gpg
rm docker.gpg

# Add repository
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker Engine
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Enable and start Docker
sudo systemctl enable --now docker
```

### Arch Linux

```bash
# Install Docker from official repositories
sudo pacman -S docker docker-compose docker-buildx

# Optional: Install Docker documentation
sudo pacman -S docker-docs

# Enable and start Docker service
sudo systemctl enable --now docker

# For rootless Docker
sudo pacman -S fuse-overlayfs slirp4netns

# Add user to docker group
sudo usermod -aG docker $USER
```

### Alpine Linux

```bash
# Add community repository if not enabled
echo "http://dl-cdn.alpinelinux.org/alpine/v$(cat /etc/alpine-release | cut -d'.' -f1,2)/community" >> /etc/apk/repositories

# Update package index
apk update

# Install Docker
apk add docker docker-cli docker-compose

# Add Docker to boot services
rc-update add docker boot

# Start Docker service
service docker start

# Install docker-compose (Python version)
apk add py3-pip
pip3 install docker-compose
```

### openSUSE/SLES

```bash
# openSUSE Leap/Tumbleweed
sudo zypper install -y docker docker-compose docker-buildx

# For latest version from official Docker repository
sudo zypper addrepo https://download.docker.com/linux/suse/docker-ce.repo
sudo zypper refresh
sudo zypper install -y docker-ce docker-ce-cli containerd.io

# Enable and start Docker
sudo systemctl enable --now docker

# Add user to docker group
sudo usermod -aG docker $USER

# SLES specific
sudo SUSEConnect -p sle-module-containers/15.5/x86_64
sudo zypper install -y docker
```

### macOS

```bash
# Using Homebrew
brew install --cask docker

# Start Docker Desktop
open /Applications/Docker.app

# Wait for Docker to start, then verify
docker --version
docker compose version

# Alternative: Install Docker CLI only (without Desktop)
brew install docker docker-compose

# For docker-machine (managing remote Docker hosts)
brew install docker-machine
```

### FreeBSD

```bash
# Install Docker from packages
pkg install docker docker-compose

# Or from ports
cd /usr/ports/sysutils/docker
make install clean

# Enable Docker
echo 'docker_enable="YES"' >> /etc/rc.conf

# Load required kernel modules
kldload linux64
kldload fdescfs

# Start Docker
service docker start

# Add user to docker group
pw groupmod docker -m $USER
```

### Windows

```powershell
# Enable WSL2 (required for Docker Desktop)
wsl --install

# Enable required Windows features
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart

# Download and install Docker Desktop
# Visit: https://desktop.docker.com/win/main/amd64/Docker%20Desktop%20Installer.exe

# Or use Chocolatey
choco install docker-desktop

# Or use winget
winget install Docker.DockerDesktop

# Start Docker Desktop from Start Menu
# Verify installation in PowerShell
docker --version
docker compose version
```

## Initial Configuration

### First-Run Setup

1. **Configure Docker daemon**:
```bash
# Create daemon configuration directory
sudo mkdir -p /etc/docker

# Create daemon.json with optimized settings
sudo tee /etc/docker/daemon.json <<EOF
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "storage-driver": "overlay2",
  "live-restore": true,
  "default-ulimits": {
    "nofile": {
      "Name": "nofile",
      "Hard": 64000,
      "Soft": 64000
    }
  }
}
EOF

# Restart Docker to apply changes
sudo systemctl restart docker
```

2. **Configure user permissions**:
```bash
# Add current user to docker group (Linux)
sudo usermod -aG docker $USER

# Apply group changes (logout/login or use newgrp)
newgrp docker

# Verify docker works without sudo
docker run hello-world
```

3. **Essential security settings**:
```bash
# Enable user namespace remapping for better isolation
sudo tee -a /etc/docker/daemon.json <<EOF
{
  "userns-remap": "default"
}
EOF

# Create subuid/subgid entries
echo "dockremap:100000:65536" | sudo tee -a /etc/subuid
echo "dockremap:100000:65536" | sudo tee -a /etc/subgid

# Restart Docker
sudo systemctl restart docker
```

### Testing Initial Setup

```bash
# Check Docker version
docker version

# View system information
docker info

# Test container creation
docker run --rm alpine echo "Docker is working!"

# Test networking
docker run --rm alpine ping -c 3 google.com

# Test volume mounting
docker run --rm -v /tmp:/host alpine ls /host
```

**WARNING:** Never expose Docker daemon socket (2375/2376) to the internet without proper TLS authentication!

## 5. Service Management

### systemd (RHEL, Debian, Ubuntu, Arch, openSUSE)

```bash
# Enable Docker to start on boot
sudo systemctl enable docker

# Start Docker service
sudo systemctl start docker

# Stop Docker service
sudo systemctl stop docker

# Restart Docker service
sudo systemctl restart docker

# Reload Docker configuration
sudo systemctl reload docker

# Check Docker status
sudo systemctl status docker

# View Docker logs
sudo journalctl -u docker.service -f
```

### OpenRC (Alpine Linux)

```bash
# Enable Docker to start on boot
rc-update add docker boot

# Start Docker service
rc-service docker start

# Stop Docker service
rc-service docker stop

# Restart Docker service
rc-service docker restart

# Check Docker status
rc-service docker status
```

### rc.d (FreeBSD)

```bash
# Enable in /etc/rc.conf
echo 'docker_enable="YES"' >> /etc/rc.conf

# Start Docker
service docker start

# Stop Docker
service docker stop

# Restart Docker
service docker restart

# Check status
service docker status
```

### launchd (macOS)

```bash
# Docker Desktop manages its own services
# Control through the UI or command line

# Stop Docker Desktop
osascript -e 'quit app "Docker"'

# Start Docker Desktop
open -a Docker

# Check if Docker is running
docker system info >/dev/null 2>&1 && echo "Docker is running" || echo "Docker is not running"
```

### Windows Service Manager

```powershell
# Docker Desktop manages services automatically
# For manual control:

# Restart Docker Desktop
Stop-Process -Name "Docker Desktop" -Force
Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe"

# Check Docker service status
Get-Service -Name docker

# Restart Docker service
Restart-Service docker
```

## Advanced Configuration

### Storage Driver Configuration

```bash
# Configure storage driver options
sudo tee /etc/docker/daemon.json <<EOF
{
  "storage-driver": "overlay2",
  "storage-opts": [
    "overlay2.override_kernel_check=true",
    "overlay2.size=20G"
  ],
  "data-root": "/var/lib/docker"
}
EOF

# For devicemapper (older systems)
{
  "storage-driver": "devicemapper",
  "storage-opts": [
    "dm.thinpooldev=/dev/mapper/docker-thinpool",
    "dm.use_deferred_removal=true",
    "dm.use_deferred_deletion=true"
  ]
}
```

### Network Configuration

```bash
# Configure default network settings
sudo tee -a /etc/docker/daemon.json <<EOF
{
  "bip": "172.17.0.1/16",
  "fixed-cidr": "172.17.0.0/16",
  "default-address-pools": [
    {
      "base": "172.80.0.0/16",
      "size": 24
    }
  ],
  "dns": ["8.8.8.8", "8.8.4.4"],
  "dns-search": ["example.com"]
}
EOF

# Enable IPv6 support
{
  "ipv6": true,
  "fixed-cidr-v6": "2001:db8::/64"
}
```

### Resource Limits

```bash
# Configure default container limits
sudo tee -a /etc/docker/daemon.json <<EOF
{
  "default-ulimits": {
    "nofile": {
      "Name": "nofile",
      "Hard": 64000,
      "Soft": 64000
    },
    "nproc": {
      "Name": "nproc",
      "Hard": 32000,
      "Soft": 32000
    }
  },
  "default-runtime": "runc",
  "runtimes": {
    "nvidia": {
      "path": "nvidia-container-runtime",
      "runtimeArgs": []
    }
  }
}
EOF
```

## Reverse Proxy Setup

### nginx as Docker Registry Proxy

```nginx
# /etc/nginx/sites-available/docker-registry
server {
    listen 443 ssl http2;
    server_name registry.example.com;

    ssl_certificate /etc/ssl/certs/registry.crt;
    ssl_certificate_key /etc/ssl/private/registry.key;

    # Docker Registry API
    location /v2/ {
        proxy_pass http://localhost:5000;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 900;
        
        # Required for docker client
        chunked_transfer_encoding on;
        client_max_body_size 0;
    }
}
```

### Apache as Docker Registry Proxy

```apache
# /etc/apache2/sites-available/docker-registry.conf
<VirtualHost *:443>
    ServerName registry.example.com
    
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/registry.crt
    SSLCertificateKeyFile /etc/ssl/private/registry.key
    
    ProxyPreserveHost On
    ProxyPass /v2 http://localhost:5000/v2
    ProxyPassReverse /v2 http://localhost:5000/v2
    
    <Location /v2>
        Order deny,allow
        Allow from all
        
        # Authentication
        AuthType Basic
        AuthName "Docker Registry"
        AuthUserFile /etc/apache2/.htpasswd
        Require valid-user
    </Location>
</VirtualHost>
```

### Caddy as Docker Registry Proxy

```caddyfile
registry.example.com {
    reverse_proxy localhost:5000 {
        header_up Host {host}
        header_up X-Real-IP {remote}
        header_up X-Forwarded-For {remote}
        header_up X-Forwarded-Proto {scheme}
    }
    
    basicauth /v2/* {
        admin $2a$14$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    }
    
    encode gzip
}
```

### Traefik Configuration

```yaml
# docker-compose.yml for Traefik
version: '3.8'

services:
  traefik:
    image: traefik:v2.9
    command:
      - "--api.insecure=true"
      - "--providers.docker=true"
      - "--entrypoints.websecure.address=:443"
    ports:
      - "443:443"
      - "8080:8080"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./certs:/certs

  registry:
    image: registry:2
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.registry.rule=Host(`registry.example.com`)"
      - "traefik.http.routers.registry.entrypoints=websecure"
      - "traefik.http.routers.registry.tls=true"
```

## Security Configuration

### Docker Daemon Security

```bash
# Enable TLS for Docker daemon
# Generate CA private key
openssl genrsa -aes256 -out ca-key.pem 4096

# Generate CA certificate
openssl req -new -x509 -days 3650 -key ca-key.pem -sha256 -out ca.pem

# Generate server key
openssl genrsa -out server-key.pem 4096

# Generate certificate signing request
openssl req -subj "/CN=$HOST" -sha256 -new -key server-key.pem -out server.csr

# Generate server certificate
echo subjectAltName = DNS:$HOST,IP:127.0.0.1 >> extfile.cnf
echo extendedKeyUsage = serverAuth >> extfile.cnf
openssl x509 -req -days 365 -sha256 -in server.csr -CA ca.pem -CAkey ca-key.pem -out server-cert.pem -extfile extfile.cnf

# Configure Docker to use TLS
sudo tee /etc/docker/daemon.json <<EOF
{
  "hosts": ["tcp://0.0.0.0:2376"],
  "tls": true,
  "tlsverify": true,
  "tlscert": "/etc/docker/certs/server-cert.pem",
  "tlskey": "/etc/docker/certs/server-key.pem",
  "tlscacert": "/etc/docker/certs/ca.pem"
}
EOF
```

### AppArmor/SELinux Configuration

```bash
# AppArmor (Debian/Ubuntu)
# Check if AppArmor is enabled
sudo aa-status

# Docker containers use docker-default profile by default
# Create custom profile
sudo tee /etc/apparmor.d/docker-custom <<EOF
#include <tunables/global>

profile docker-custom flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  
  network,
  capability,
  
  # Deny dangerous capabilities
  deny capability dac_override,
  deny capability setuid,
  deny capability setgid,
  
  # File access
  deny /proc/sys/** w,
  deny /sys/** w,
  
  # Allow necessary access
  /usr/bin/** ix,
  /bin/** ix,
  /lib/** r,
}
EOF

# Load profile
sudo apparmor_parser -r /etc/apparmor.d/docker-custom

# SELinux (RHEL/CentOS)
# Enable SELinux for containers
sudo setsebool -P container_manage_cgroup true

# Check Docker SELinux context
ps -eZ | grep dockerd
```

### Firewall Rules

```bash
# UFW (Ubuntu/Debian)
# Docker manages its own iptables rules
# To integrate with UFW:
sudo tee -a /etc/ufw/after.rules <<EOF
*filter
:ufw-user-forward - [0:0]
:DOCKER-USER - [0:0]
-A DOCKER-USER -j ufw-user-forward
-A DOCKER-USER -j RETURN -s 10.0.0.0/8
-A DOCKER-USER -j RETURN -s 172.16.0.0/12
-A DOCKER-USER -j RETURN -s 192.168.0.0/16
-A DOCKER-USER -j DROP
COMMIT
EOF

sudo ufw reload

# firewalld (RHEL/CentOS/openSUSE)
# Add Docker zone
sudo firewall-cmd --permanent --new-zone=docker
sudo firewall-cmd --permanent --zone=docker --add-interface=docker0
sudo firewall-cmd --permanent --zone=docker --add-port=2377/tcp
sudo firewall-cmd --permanent --zone=docker --add-port=7946/tcp
sudo firewall-cmd --permanent --zone=docker --add-port=7946/udp
sudo firewall-cmd --permanent --zone=docker --add-port=4789/udp
sudo firewall-cmd --reload

# iptables (manual)
# Allow Docker subnet
sudo iptables -A INPUT -s 172.17.0.0/16 -j ACCEPT
sudo iptables-save > /etc/iptables/rules.v4

# pf (FreeBSD)
# Add to /etc/pf.conf
pass in on docker0 all
pass out on docker0 all
```

## Database Setup

Docker doesn't require a database, but here's how to run databases in Docker:

### PostgreSQL in Docker

```bash
# Create volume for persistent data
docker volume create postgres_data

# Run PostgreSQL container
docker run -d \
  --name postgres \
  --restart unless-stopped \
  -e POSTGRES_PASSWORD=securepassword \
  -e POSTGRES_USER=myuser \
  -e POSTGRES_DB=mydb \
  -v postgres_data:/var/lib/postgresql/data \
  -p 5432:5432 \
  postgres:15-alpine

# Connect to PostgreSQL
docker exec -it postgres psql -U myuser -d mydb
```

### MySQL in Docker

```bash
# Create volume for persistent data
docker volume create mysql_data

# Run MySQL container
docker run -d \
  --name mysql \
  --restart unless-stopped \
  -e MYSQL_ROOT_PASSWORD=rootpassword \
  -e MYSQL_DATABASE=mydb \
  -e MYSQL_USER=myuser \
  -e MYSQL_PASSWORD=securepassword \
  -v mysql_data:/var/lib/mysql \
  -p 3306:3306 \
  mysql:8.0

# Connect to MySQL
docker exec -it mysql mysql -u myuser -p
```

## Performance Optimization

### Kernel Parameters

```bash
# Optimize kernel parameters for Docker
sudo tee -a /etc/sysctl.conf <<EOF
# Docker optimization
vm.max_map_count=262144
fs.file-max=2097152
fs.inotify.max_user_watches=524288
fs.inotify.max_user_instances=512

# Network optimization
net.core.somaxconn=32768
net.ipv4.tcp_max_syn_backlog=8192
net.core.netdev_max_backlog=5000
net.ipv4.ip_local_port_range=1024 65535

# Bridge settings
net.bridge.bridge-nf-call-iptables=1
net.bridge.bridge-nf-call-ip6tables=1
net.ipv4.ip_forward=1
EOF

# Apply settings
sudo sysctl -p
```

### Storage Optimization

```bash
# Use dedicated disk for Docker
# Format with XFS for better performance
sudo mkfs.xfs /dev/sdb1
sudo mkdir -p /var/lib/docker
sudo mount /dev/sdb1 /var/lib/docker

# Add to /etc/fstab
echo "/dev/sdb1 /var/lib/docker xfs defaults,noatime 0 2" | sudo tee -a /etc/fstab

# Configure storage driver options
sudo tee /etc/docker/daemon.json <<EOF
{
  "storage-driver": "overlay2",
  "storage-opts": [
    "overlay2.override_kernel_check=true"
  ],
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
EOF
```

### Build Optimization

```bash
# Enable BuildKit for faster builds
export DOCKER_BUILDKIT=1

# Configure BuildKit in daemon
sudo tee -a /etc/docker/daemon.json <<EOF
{
  "features": {
    "buildkit": true
  }
}
EOF

# Use build cache mount
# In Dockerfile:
# syntax=docker/dockerfile:1
FROM alpine
RUN --mount=type=cache,target=/var/cache/apk \
    apk add --no-cache git
```

## Monitoring

### Docker Stats and Events

```bash
# Monitor container resource usage
docker stats

# Stream Docker events
docker events

# Monitor specific container
docker stats container_name

# Export metrics in JSON
docker stats --no-stream --format json > stats.json

# Monitor Docker daemon
sudo journalctl -u docker.service -f
```

### cAdvisor Setup

```bash
# Run cAdvisor for container metrics
docker run -d \
  --name=cadvisor \
  --restart unless-stopped \
  -p 8080:8080 \
  -v /:/rootfs:ro \
  -v /var/run:/var/run:ro \
  -v /sys:/sys:ro \
  -v /var/lib/docker/:/var/lib/docker:ro \
  -v /dev/disk/:/dev/disk:ro \
  --privileged \
  gcr.io/cadvisor/cadvisor:latest

# Access metrics at http://localhost:8080
```

### Prometheus Integration

```yaml
# docker-compose.yml for monitoring stack
version: '3.8'

services:
  prometheus:
    image: prom/prometheus
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    ports:
      - "9090:9090"
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'

  node-exporter:
    image: prom/node-exporter
    ports:
      - "9100:9100"
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro

volumes:
  prometheus_data:
```

## 9. Backup and Restore

### Container Backup

```bash
#!/bin/bash
# backup-docker.sh

BACKUP_DIR="/backup/docker"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p $BACKUP_DIR/{images,volumes,configs}

# Backup running containers
docker ps -q | while read container; do
    name=$(docker inspect -f '{{.Name}}' $container | sed 's/\///')
    docker commit $container backup_$name:$DATE
    docker save backup_$name:$DATE | gzip > $BACKUP_DIR/images/${name}_${DATE}.tar.gz
    docker inspect $container > $BACKUP_DIR/configs/${name}_${DATE}.json
done

# Backup volumes
docker volume ls -q | while read volume; do
    docker run --rm \
        -v $volume:/data \
        -v $BACKUP_DIR/volumes:/backup \
        alpine tar czf /backup/${volume}_${DATE}.tar.gz -C /data .
done

# Backup Docker daemon config
cp /etc/docker/daemon.json $BACKUP_DIR/configs/daemon_${DATE}.json

echo "Backup completed: $DATE"
```

### Volume Backup

```bash
# Backup named volume
docker run --rm \
    -v myvolume:/source:ro \
    -v $(pwd):/backup \
    alpine tar czf /backup/myvolume.tar.gz -C /source .

# Restore volume
docker run --rm \
    -v myvolume:/target \
    -v $(pwd):/backup \
    alpine tar xzf /backup/myvolume.tar.gz -C /target
```

### Registry Backup

```bash
# Backup Docker registry data
docker exec registry tar czf - /var/lib/registry | gzip > registry_backup_$(date +%Y%m%d).tar.gz

# Backup registry config
docker exec registry cat /etc/docker/registry/config.yml > registry_config_backup.yml
```

## 6. Troubleshooting

### Common Issues

1. **Cannot connect to Docker daemon**:
```bash
# Check if Docker is running
sudo systemctl status docker

# Check Docker socket permissions
ls -la /var/run/docker.sock

# Check if user is in docker group
groups $USER

# Start Docker if not running
sudo systemctl start docker
```

2. **Container networking issues**:
```bash
# Check Docker networks
docker network ls

# Inspect bridge network
docker network inspect bridge

# Check iptables rules
sudo iptables -L -n -v

# Reset Docker networking
sudo systemctl stop docker
sudo ip link delete docker0
sudo systemctl start docker
```

3. **Storage space issues**:
```bash
# Check disk usage
docker system df

# Clean up unused resources
docker system prune -a --volumes

# Check Docker root directory
df -h /var/lib/docker

# Find large containers/images
docker ps -s
docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}"
```

4. **Permission denied errors**:
```bash
# Fix socket permissions
sudo chmod 666 /var/run/docker.sock

# Fix user namespace issues
sudo usermod -aG docker $USER
newgrp docker

# Check SELinux/AppArmor
getenforce  # SELinux
sudo aa-status  # AppArmor
```

### Debug Mode

```bash
# Run Docker in debug mode
sudo dockerd --debug

# Enable debug logging
sudo tee /etc/docker/daemon.json <<EOF
{
  "debug": true,
  "log-level": "debug"
}
EOF

sudo systemctl restart docker

# Check debug logs
sudo journalctl -u docker.service --no-pager
```

## Maintenance

### Update Procedures

```bash
# RHEL/CentOS/Rocky/AlmaLinux
sudo yum update docker-ce docker-ce-cli containerd.io

# Debian/Ubuntu
sudo apt-get update
sudo apt-get upgrade docker-ce docker-ce-cli containerd.io

# Arch Linux
sudo pacman -Syu docker

# Alpine Linux
apk update
apk upgrade docker

# openSUSE
sudo zypper update docker

# FreeBSD
pkg update
pkg upgrade docker

# Always restart after updates
sudo systemctl restart docker
```

### Cleanup Tasks

```bash
#!/bin/bash
# docker-cleanup.sh

echo "Starting Docker cleanup..."

# Remove stopped containers
docker container prune -f

# Remove unused images
docker image prune -a -f

# Remove unused volumes
docker volume prune -f

# Remove unused networks
docker network prune -f

# Remove build cache
docker builder prune -f

# Show disk usage after cleanup
docker system df

echo "Cleanup completed"
```

### Log Rotation

```bash
# Configure log rotation for containers
sudo tee /etc/docker/daemon.json <<EOF
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3",
    "compress": "true"
  }
}
EOF

# System-wide Docker logs rotation
sudo tee /etc/logrotate.d/docker <<EOF
/var/lib/docker/containers/*/*.log {
    rotate 7
    daily
    compress
    missingok
    delaycompress
    copytruncate
}
EOF
```

## Integration Examples

### CI/CD Pipeline Integration

```yaml
# GitLab CI example
stages:
  - build
  - test
  - deploy

variables:
  DOCKER_DRIVER: overlay2
  DOCKER_TLS_CERTDIR: "/certs"

build:
  stage: build
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker build -t myapp:$CI_COMMIT_SHA .
    - docker push myapp:$CI_COMMIT_SHA

# Jenkins Pipeline example
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                script {
                    docker.build("myapp:${env.BUILD_ID}")
                }
            }
        }
    }
}
```

### Kubernetes Integration

```bash
# Install CRI-Docker for Kubernetes
CRI_VERSION="0.3.1"
wget https://github.com/Mirantis/cri-dockerd/releases/download/v${CRI_VERSION}/cri-dockerd-${CRI_VERSION}.amd64.tgz
tar xzf cri-dockerd-${CRI_VERSION}.amd64.tgz
sudo install -o root -g root -m 0755 cri-dockerd /usr/local/bin/cri-dockerd
rm cri-dockerd-${CRI_VERSION}.amd64.tgz cri-dockerd

# Create systemd service
sudo tee /etc/systemd/system/cri-docker.service <<EOF
[Unit]
Description=CRI Docker Interface
After=network.target docker.service
Requires=docker.service

[Service]
Type=notify
ExecStart=/usr/local/bin/cri-dockerd --container-runtime-endpoint unix:///var/run/cri-dockerd.sock
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable --now cri-docker
```

### Docker Compose Examples

```yaml
# Multi-tier application stack
version: '3.8'

services:
  web:
    build: ./web
    ports:
      - "80:80"
    environment:
      - DATABASE_URL=postgresql://user:pass@db:5432/mydb
    depends_on:
      - db
    networks:
      - frontend
      - backend

  db:
    image: postgres:15
    environment:
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=pass
      - POSTGRES_DB=mydb
    volumes:
      - db_data:/var/lib/postgresql/data
    networks:
      - backend

  redis:
    image: redis:alpine
    networks:
      - backend

networks:
  frontend:
  backend:

volumes:
  db_data:
```

### SDK Integration

```python
# Python Docker SDK
import docker

client = docker.from_env()

# Run container
container = client.containers.run(
    "alpine",
    "echo hello world",
    detach=True
)

# List containers
for container in client.containers.list():
    print(container.name)

# Build image
image, logs = client.images.build(
    path=".",
    tag="myapp:latest"
)
```

```javascript
// Node.js Docker SDK
const Docker = require('dockerode');
const docker = new Docker();

// Run container
docker.createContainer({
  Image: 'alpine',
  Cmd: ['echo', 'hello world'],
  name: 'mycontainer'
}, (err, container) => {
  if (!err) {
    container.start();
  }
});

// List containers
docker.listContainers((err, containers) => {
  containers.forEach(containerInfo => {
    console.log(containerInfo.Names);
  });
});
```

## Additional Resources

- [Official Documentation](https://docs.docker.com/)
- [Docker Hub](https://hub.docker.com/)
- [Docker GitHub Repository](https://github.com/docker)
- [Docker Best Practices](https://docs.docker.com/develop/dev-best-practices/)
- [Docker Security Documentation](https://docs.docker.com/engine/security/)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [Docker Community Forums](https://forums.docker.com/)
- [Play with Docker](https://labs.play-with-docker.com/)

---

**Note:** This guide is part of the [HowToMgr](https://howtomgr.github.io) collection. Always refer to official documentation for the most up-to-date information.