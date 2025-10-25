# Deployment Configuration

## Overview
Complete deployment configuration for the Polaris music registry including Docker setup, environment variables, and orchestration.

## Docker Compose Configuration

```yaml
# File: docker-compose.yml
# Complete stack deployment for Polaris music registry

version: '3.8'

services:
  # ========== DATABASE LAYER ==========
  
  # Neo4j Graph Database
  neo4j:
    image: neo4j:5.12-enterprise
    container_name: polaris-neo4j
    environment:
      - NEO4J_AUTH=neo4j/polarismusic123
      - NEO4J_ACCEPT_LICENSE_AGREEMENT=yes
      - NEO4J_dbms_memory_pagecache_size=2G
      - NEO4J_dbms_memory_heap_initial__size=2G
      - NEO4J_dbms_memory_heap_max__size=4G
      - NEO4J_dbms_security_procedures_unrestricted=apoc.*
      - NEO4J_dbms_security_procedures_allowlist=apoc.*
      - NEO4J_PLUGINS=["apoc"]
    ports:
      - "7474:7474"  # Browser
      - "7687:7687"  # Bolt
    volumes:
      - neo4j-data:/data
      - neo4j-logs:/logs
      - neo4j-import:/import
      - neo4j-plugins:/plugins
    networks:
      - polaris-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "cypher-shell", "-u", "neo4j", "-p", "polarismusic123", "RETURN 1"]
      interval: 30s
      timeout: 10s
      retries: 5
  
  # Redis Cache
  redis:
    image: redis:7-alpine
    container_name: polaris-redis
    command: redis-server --appendonly yes --requirepass polarisredis123
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    networks:
      - polaris-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "redis-cli", "AUTH", "polarisredis123", "ping"]
      interval: 30s
      timeout: 3s
      retries: 3
  
  # PostgreSQL for Substreams sink
  postgres:
    image: postgres:15-alpine
    container_name: polaris-postgres
    environment:
      - POSTGRES_DB=polaris
      - POSTGRES_USER=polaris
      - POSTGRES_PASSWORD=polarisdb123
    ports:
      - "5432:5432"
    volumes:
      - postgres-data:/var/lib/postgresql/data
      - ./sql/init.sql:/docker-entrypoint-initdb.d/init.sql
    networks:
      - polaris-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U polaris"]
      interval: 30s
      timeout: 5s
      retries: 3
  
  # ========== STORAGE LAYER ==========
  
  # IPFS Node
  ipfs:
    image: ipfs/kubo:latest
    container_name: polaris-ipfs
    environment:
      - IPFS_PROFILE=server
      - IPFS_PATH=/data/ipfs
    ports:
      - "4001:4001"     # Swarm
      - "5001:5001"     # API
      - "8080:8080"     # Gateway
    volumes:
      - ipfs-data:/data/ipfs
    networks:
      - polaris-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "ipfs version"]
      interval: 30s
      timeout: 3s
      retries: 3
  
  # MinIO (S3-compatible storage)
  minio:
    image: minio/minio:latest
    container_name: polaris-minio
    command: server /data --console-address ":9001"
    environment:
      - MINIO_ROOT_USER=polarisadmin
      - MINIO_ROOT_PASSWORD=polarisminio123
      - MINIO_DEFAULT_BUCKETS=polaris-events:public
    ports:
      - "9000:9000"     # API
      - "9001:9001"     # Console
    volumes:
      - minio-data:/data
    networks:
      - polaris-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9000/minio/health/live"]
      interval: 30s
      timeout: 5s
      retries: 3
  
  # ========== APPLICATION LAYER ==========
  
  # API Server
  api-server:
    build:
      context: ./backend
      dockerfile: Dockerfile
    container_name: polaris-api
    environment:
      - NODE_ENV=production
      - PORT=3000
      - NEO4J_URI=bolt://neo4j:7687
      - NEO4J_USER=neo4j
      - NEO4J_PASSWORD=polarismusic123
      - REDIS_HOST=redis
      - REDIS_PORT=6379
      - REDIS_PASSWORD=polarisredis123
      - IPFS_URL=http://ipfs:5001
      - S3_ENDPOINT=http://minio:9000
      - S3_ACCESS_KEY=polarisadmin
      - S3_SECRET_KEY=polarisminio123
      - S3_BUCKET=polaris-events
      - POSTGRES_URL=postgresql://polaris:polarisdb123@postgres:5432/polaris
    ports:
      - "3000:3000"
    depends_on:
      neo4j:
        condition: service_healthy
      redis:
        condition: service_healthy
      postgres:
        condition: service_healthy
      ipfs:
        condition: service_healthy
    networks:
      - polaris-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/api/health"]
      interval: 30s
      timeout: 5s
      retries: 3
  
  # Event Processor
  event-processor:
    build:
      context: ./backend
      dockerfile: Dockerfile.processor
    container_name: polaris-processor
    environment:
      - NODE_ENV=production
      - RPC_URL=https://eos.greymass.com
      - START_BLOCK=295000000
      - NEO4J_URI=bolt://neo4j:7687
      - NEO4J_USER=neo4j
      - NEO4J_PASSWORD=polarismusic123
      - REDIS_HOST=redis
      - REDIS_PORT=6379
      - REDIS_PASSWORD=polarisredis123
      - IPFS_URL=http://ipfs:5001
      - S3_ENDPOINT=http://minio:9000
      - S3_ACCESS_KEY=polarisadmin
      - S3_SECRET_KEY=polarisminio123
      - S3_BUCKET=polaris-events
    depends_on:
      neo4j:
        condition: service_healthy
      redis:
        condition: service_healthy
      ipfs:
        condition: service_healthy
    networks:
      - polaris-network
    restart: unless-stopped
  
  # Substreams Sink
  substreams-sink:
    build:
      context: ./substreams
      dockerfile: Dockerfile
    container_name: polaris-substreams
    environment:
      - SUBSTREAMS_ENDPOINT=eos.firehose.eosnation.io:9000
      - DATABASE_URL=postgresql://polaris:polarisdb123@postgres:5432/polaris
      - START_BLOCK=295000000
      - MODULE_NAME=map_anchor_events
    depends_on:
      postgres:
        condition: service_healthy
    networks:
      - polaris-network
    restart: unless-stopped
  
  # Frontend
  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    container_name: polaris-frontend
    environment:
      - NODE_ENV=production
      - REACT_APP_API_URL=http://api-server:3000
      - REACT_APP_CHAIN_ID=1064487b3cd1a897ce03ae5b6a865651747e2e152090f99c1d19d44e01aea5a4
      - REACT_APP_RPC_URL=https://eos.greymass.com
    ports:
      - "3001:3000"
    depends_on:
      - api-server
    networks:
      - polaris-network
    restart: unless-stopped
  
  # ========== MONITORING ==========
  
  # Prometheus
  prometheus:
    image: prom/prometheus:latest
    container_name: polaris-prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
    ports:
      - "9090:9090"
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus-data:/prometheus
    networks:
      - polaris-network
    restart: unless-stopped
  
  # Grafana
  grafana:
    image: grafana/grafana:latest
    container_name: polaris-grafana
    environment:
      - GF_SECURITY_ADMIN_USER=admin
      - GF_SECURITY_ADMIN_PASSWORD=polarisgrafana123
      - GF_INSTALL_PLUGINS=redis-datasource
    ports:
      - "3002:3000"
    volumes:
      - grafana-data:/var/lib/grafana
      - ./monitoring/dashboards:/etc/grafana/provisioning/dashboards
      - ./monitoring/datasources:/etc/grafana/provisioning/datasources
    depends_on:
      - prometheus
    networks:
      - polaris-network
    restart: unless-stopped

# ========== VOLUMES ==========
volumes:
  neo4j-data:
  neo4j-logs:
  neo4j-import:
  neo4j-plugins:
  redis-data:
  postgres-data:
  ipfs-data:
  minio-data:
  prometheus-data:
  grafana-data:

# ========== NETWORKS ==========
networks:
  polaris-network:
    driver: bridge
```

## Backend Dockerfile

```dockerfile
# File: backend/Dockerfile
# API server container

FROM node:18-alpine

# Install build dependencies
RUN apk add --no-cache python3 make g++

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy source code
COPY src/ ./src/

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Switch to non-root user
USER nodejs

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/api/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"

# Start server
CMD ["node", "src/api/server.js"]
```

## Environment Configuration

```bash
# File: .env.production
# Production environment variables

# Blockchain
CHAIN_ID=1064487b3cd1a897ce03ae5b6a865651747e2e152090f99c1d19d44e01aea5a4
RPC_URL=https://eos.greymass.com
CONTRACT_ACCOUNT=polaris
START_BLOCK=295000000

# Database
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=changeme
POSTGRES_URL=postgresql://polaris:changeme@localhost:5432/polaris

# Cache
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=changeme

# Storage
IPFS_URL=http://localhost:5001
S3_ENDPOINT=https://s3.amazonaws.com
S3_ACCESS_KEY=your-access-key
S3_SECRET_KEY=your-secret-key
S3_BUCKET=polaris-events
S3_REGION=us-east-1

# API
API_PORT=3000
API_CORS_ORIGIN=https://app.polaris.music

# Substreams
SUBSTREAMS_ENDPOINT=eos.firehose.eosnation.io:9000
SUBSTREAMS_API_KEY=your-api-key

# Monitoring
PROMETHEUS_PORT=9090
GRAFANA_PORT=3002

# Security
JWT_SECRET=your-jwt-secret
SESSION_SECRET=your-session-secret
```

## Kubernetes Deployment

```yaml
# File: k8s/deployment.yml
# Kubernetes deployment for production

apiVersion: apps/v1
kind: Deployment
metadata:
  name: polaris-api
  namespace: polaris
spec:
  replicas: 3
  selector:
    matchLabels:
      app: polaris-api
  template:
    metadata:
      labels:
        app: polaris-api
    spec:
      containers:
      - name: api
        image: polaris/api:latest
        ports:
        - containerPort: 3000
        env:
        - name: NODE_ENV
          value: production
        - name: NEO4J_URI
          valueFrom:
            secretKeyRef:
              name: polaris-secrets
              key: neo4j-uri
        - name: NEO4J_PASSWORD
          valueFrom:
            secretKeyRef:
              name: polaris-secrets
              key: neo4j-password
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /api/health
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /api/health
            port: 3000
          initialDelaySeconds: 5
          periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: polaris-api
  namespace: polaris
spec:
  selector:
    app: polaris-api
  ports:
  - port: 3000
    targetPort: 3000
  type: LoadBalancer
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: polaris-api-hpa
  namespace: polaris
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: polaris-api
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

## Nginx Configuration

```nginx
# File: nginx/nginx.conf
# Reverse proxy and load balancing

upstream api_servers {
    least_conn;
    server api-server-1:3000 weight=1 max_fails=3 fail_timeout=30s;
    server api-server-2:3000 weight=1 max_fails=3 fail_timeout=30s;
    server api-server-3:3000 weight=1 max_fails=3 fail_timeout=30s;
}

server {
    listen 80;
    server_name api.polaris.music;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name api.polaris.music;
    
    ssl_certificate /etc/ssl/certs/polaris.crt;
    ssl_certificate_key /etc/ssl/private/polaris.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req zone=api burst=20 nodelay;
    
    # Proxy settings
    location /api {
        proxy_pass http://api_servers;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Buffering
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
    }
    
    # GraphQL endpoint
    location /graphql {
        proxy_pass http://api_servers/graphql;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        
        # Larger body size for GraphQL
        client_max_body_size 10M;
    }
    
    # WebSocket support for subscriptions
    location /ws {
        proxy_pass http://api_servers/ws;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Deployment Scripts

```bash
#!/bin/bash
# File: deploy.sh
# Deployment script for production

set -e

# Configuration
ENV=${1:-production}
VERSION=${2:-latest}

echo "Deploying Polaris Music Registry - Environment: $ENV, Version: $VERSION"

# Load environment variables
if [ -f ".env.$ENV" ]; then
    export $(cat .env.$ENV | grep -v '^#' | xargs)
fi

# Build images
echo "Building Docker images..."
docker-compose build --parallel

# Tag images
docker tag polaris-api:latest polaris/api:$VERSION
docker tag polaris-processor:latest polaris/processor:$VERSION
docker tag polaris-frontend:latest polaris/frontend:$VERSION

# Push to registry (if not local)
if [ "$ENV" != "local" ]; then
    echo "Pushing images to registry..."
    docker push polaris/api:$VERSION
    docker push polaris/processor:$VERSION
    docker push polaris/frontend:$VERSION
fi

# Deploy stack
echo "Deploying stack..."
if [ "$ENV" == "production" ]; then
    # Kubernetes deployment
    kubectl apply -f k8s/namespace.yml
    kubectl apply -f k8s/secrets.yml
    kubectl apply -f k8s/configmap.yml
    kubectl apply -f k8s/deployment.yml
    kubectl rollout status deployment/polaris-api -n polaris
else
    # Docker Compose deployment
    docker-compose up -d
    
    # Wait for services to be healthy
    echo "Waiting for services to be healthy..."
    docker-compose ps
    
    # Run database migrations
    echo "Running database migrations..."
    docker-compose exec api-server npm run migrate
fi

# Initialize database schema
echo "Initializing database schema..."
docker-compose exec api-server npm run init:db

# Verify deployment
echo "Verifying deployment..."
curl -f http://localhost:3000/api/health || exit 1

echo "Deployment complete!"
```

## Monitoring Configuration

```yaml
# File: monitoring/prometheus.yml
# Prometheus configuration for metrics collection

global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  # API Server metrics
  - job_name: 'api-server'
    static_configs:
      - targets: ['api-server:3000']
    metrics_path: '/metrics'
    
  # Neo4j metrics
  - job_name: 'neo4j'
    static_configs:
      - targets: ['neo4j:2004']
    
  # Redis metrics
  - job_name: 'redis'
    static_configs:
      - targets: ['redis-exporter:9121']
    
  # Node exporter for system metrics
  - job_name: 'node'
    static_configs:
      - targets: ['node-exporter:9100']

# Alerting rules
rule_files:
  - '/etc/prometheus/alerts.yml'

alerting:
  alertmanagers:
    - static_configs:
        - targets: ['alertmanager:9093']
```

## Backup Strategy

```bash
#!/bin/bash
# File: scripts/backup.sh
# Automated backup script

set -e

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backups/$TIMESTAMP"

echo "Starting backup - $TIMESTAMP"

# Create backup directory
mkdir -p $BACKUP_DIR

# Backup Neo4j
echo "Backing up Neo4j..."
docker exec polaris-neo4j neo4j-admin dump --database=neo4j --to=/backup/neo4j-$TIMESTAMP.dump
docker cp polaris-neo4j:/backup/neo4j-$TIMESTAMP.dump $BACKUP_DIR/

# Backup PostgreSQL
echo "Backing up PostgreSQL..."
docker exec polaris-postgres pg_dump -U polaris polaris | gzip > $BACKUP_DIR/postgres-$TIMESTAMP.sql.gz

# Backup Redis
echo "Backing up Redis..."
docker exec polaris-redis redis-cli --rdb /backup/redis-$TIMESTAMP.rdb BGSAVE
sleep 5
docker cp polaris-redis:/backup/redis-$TIMESTAMP.rdb $BACKUP_DIR/

# Backup IPFS pins
echo "Backing up IPFS pins..."
docker exec polaris-ipfs ipfs pin ls --type=recursive > $BACKUP_DIR/ipfs-pins-$TIMESTAMP.txt

# Compress backup
tar -czf /backups/polaris-backup-$TIMESTAMP.tar.gz -C /backups $TIMESTAMP

# Upload to S3
aws s3 cp /backups/polaris-backup-$TIMESTAMP.tar.gz s3://polaris-backups/

# Clean up old backups (keep last 7 days)
find /backups -type f -mtime +7 -delete

echo "Backup complete - $TIMESTAMP"
```

## Health Monitoring

```javascript
// File: monitoring/health-check.js
// Comprehensive health monitoring

const axios = require('axios');

/**
 * Perform comprehensive health check of all services
 */
async function healthCheck() {
    const services = [
        { name: 'API Server', url: 'http://localhost:3000/api/health' },
        { name: 'Neo4j', url: 'http://localhost:7474' },
        { name: 'Redis', check: checkRedis },
        { name: 'IPFS', url: 'http://localhost:5001/api/v0/id' },
        { name: 'PostgreSQL', check: checkPostgres }
    ];
    
    const results = {};
    
    for (const service of services) {
        try {
            if (service.url) {
                await axios.get(service.url, { timeout: 5000 });
                results[service.name] = 'healthy';
            } else if (service.check) {
                await service.check();
                results[service.name] = 'healthy';
            }
        } catch (error) {
            results[service.name] = 'unhealthy';
            console.error(`${service.name} health check failed:`, error.message);
        }
    }
    
    return results;
}

// Run health checks every minute
setInterval(async () => {
    const health = await healthCheck();
    console.log('Health status:', health);
    
    // Alert if any service is unhealthy
    const unhealthy = Object.entries(health)
        .filter(([_, status]) => status === 'unhealthy');
    
    if (unhealthy.length > 0) {
        // Send alert (webhook, email, etc.)
        console.error('ALERT: Unhealthy services:', unhealthy);
    }
}, 60000);
```