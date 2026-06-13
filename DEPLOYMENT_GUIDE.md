# Deployment Guide

This guide provides comprehensive instructions for deploying the File Scanner and ThreatFlux libraries in production environments.

## 📋 Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Deployment Options](#deployment-options)
- [Container Deployment](#container-deployment)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Cloud Platform Deployment](#cloud-platform-deployment)
- [Configuration Management](#configuration-management)
- [Monitoring & Observability](#monitoring--observability)
- [Backup & Recovery](#backup--recovery)
- [Scaling Strategies](#scaling-strategies)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)

## 🎯 Overview

The File Scanner can be deployed in various configurations:

- **Standalone Binary**: Direct deployment on virtual machines or bare metal
- **Container**: Docker containers for portable deployment
- **Kubernetes**: Orchestrated deployment with auto-scaling and service discovery
- **Cloud Functions**: Serverless deployment for event-driven analysis
- **Microservices**: Individual ThreatFlux libraries as separate services

### Deployment Architecture

```mermaid
graph TB
    subgraph "Load Balancer"
        LB[Load Balancer]
    end
    
    subgraph "Application Tier"
        APP1[File Scanner 1]
        APP2[File Scanner 2]
        APP3[File Scanner 3]
    end
    
    subgraph "Cache Tier"
        REDIS[Redis Cluster]
        CACHE[File Cache]
    end
    
    subgraph "Storage Tier"
        S3[Object Storage]
        DB[(PostgreSQL)]
        LOGS[(Log Storage)]
    end
    
    subgraph "Monitoring"
        PROM[Prometheus]
        GRAF[Grafana]
        ALERT[AlertManager]
    end
    
    LB --> APP1
    LB --> APP2
    LB --> APP3
    
    APP1 --> REDIS
    APP2 --> REDIS
    APP3 --> REDIS
    
    APP1 --> CACHE
    APP2 --> CACHE
    APP3 --> CACHE
    
    APP1 --> S3
    APP2 --> S3
    APP3 --> S3
    
    APP1 --> DB
    APP2 --> DB
    APP3 --> DB
    
    APP1 --> LOGS
    APP2 --> LOGS
    APP3 --> LOGS
    
    PROM --> APP1
    PROM --> APP2
    PROM --> APP3
    GRAF --> PROM
    ALERT --> PROM
```

## 📋 Prerequisites

### System Requirements

#### Minimum Requirements
- **CPU**: 2 cores, 2.4 GHz
- **Memory**: 4 GB RAM
- **Storage**: 20 GB available disk space
- **Network**: 100 Mbps connection
- **OS**: Linux (Ubuntu 20.04+, CentOS 8+, RHEL 8+)

#### Recommended Requirements
- **CPU**: 8 cores, 3.0 GHz
- **Memory**: 16 GB RAM
- **Storage**: 100 GB SSD
- **Network**: 1 Gbps connection
- **OS**: Linux with container runtime

#### High-Performance Requirements
- **CPU**: 16+ cores, 3.5 GHz
- **Memory**: 64 GB RAM
- **Storage**: 500 GB NVMe SSD
- **Network**: 10 Gbps connection
- **Additional**: GPU for ML workloads (optional)

### Software Dependencies

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    curl \
    wget \
    git \
    build-essential \
    pkg-config \
    libssl-dev \
    ca-certificates

# RHEL/CentOS
sudo yum update -y
sudo yum install -y \
    curl \
    wget \
    git \
    gcc \
    openssl-devel \
    ca-certificates
```

### Rust Installation

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Verify installation
rustc --version
cargo --version
```

## 🚀 Deployment Options

### Option 1: Standalone Binary

#### Build for Production

```bash
# Clone the repository
git clone https://github.com/ThreatFlux/file-scanner.git
cd file-scanner

# Build optimized release
cargo build --release --workspace

# Verify build
./target/release/file-scanner --version
```

#### Installation

```bash
# Install binary
sudo cp target/release/file-scanner /usr/local/bin/
sudo chmod +x /usr/local/bin/file-scanner

# Create service user
sudo useradd -r -s /bin/false threatflux

# Create directories
sudo mkdir -p /etc/threatflux
sudo mkdir -p /var/log/threatflux
sudo mkdir -p /var/cache/threatflux

# Set permissions
sudo chown -R threatflux:threatflux /var/log/threatflux
sudo chown -R threatflux:threatflux /var/cache/threatflux
```

#### Systemd Service

```bash
# Create service file
sudo tee /etc/systemd/system/threatflux.service << EOF
[Unit]
Description=ThreatFlux File Scanner
After=network.target
Wants=network.target

[Service]
Type=exec
User=threatflux
Group=threatflux
ExecStart=/usr/local/bin/file-scanner mcp-http --port 8080
Restart=always
RestartSec=5
Environment=RUST_LOG=info
Environment=THREATFLUX_CACHE_DIR=/var/cache/threatflux
Environment=THREATFLUX_LOG_DIR=/var/log/threatflux

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/cache/threatflux /var/log/threatflux

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable threatflux
sudo systemctl start threatflux
sudo systemctl status threatflux
```

### Option 2: Container Deployment

#### Dockerfile

```dockerfile
# Multi-stage build for optimization
FROM rust:1.96.0-bookworm AS builder

WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./
COPY threatflux-*/Cargo.toml ./threatflux-*/

# Copy source code
COPY src/ ./src/
COPY threatflux-*/ ./threatflux-*/

# Build for release
RUN cargo build --release --workspace

# Runtime image
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create user
RUN groupadd -r threatflux && useradd -r -g threatflux threatflux

# Create directories
RUN mkdir -p /var/cache/threatflux /var/log/threatflux && \
    chown -R threatflux:threatflux /var/cache/threatflux /var/log/threatflux

# Copy binary
COPY --from=builder /app/target/release/file-scanner /usr/local/bin/

# Set permissions
RUN chmod +x /usr/local/bin/file-scanner

# Switch to non-root user
USER threatflux

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Default command
CMD ["file-scanner", "mcp-http", "--port", "8080"]
```

#### Docker Compose

```yaml
version: '3.8'

services:
  threatflux:
    build: .
    ports:
      - "8080:8080"
    environment:
      - RUST_LOG=info
      - THREATFLUX_CACHE_SIZE=100000
      - THREATFLUX_WORKERS=4
    volumes:
      - threatflux_cache:/var/cache/threatflux
      - threatflux_logs:/var/log/threatflux
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    deploy:
      resources:
        limits:
          cpus: '4'
          memory: 8G
        reservations:
          cpus: '2'
          memory: 4G

  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data
    restart: unless-stopped
    deploy:
      resources:
        limits:
          cpus: '1'
          memory: 1G

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
    depends_on:
      - threatflux
    restart: unless-stopped

volumes:
  threatflux_cache:
    driver: local
  threatflux_logs:
    driver: local
  redis_data:
    driver: local
```

#### Build and Deploy

```bash
# Build image
docker build -t threatflux/file-scanner:latest .

# Run with Docker Compose
docker-compose up -d

# Check status
docker-compose ps
docker-compose logs threatflux
```

## ☸️ Kubernetes Deployment

### Namespace and RBAC

```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: threatflux
  labels:
    name: threatflux
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: threatflux-sa
  namespace: threatflux
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: threatflux
  name: threatflux-role
rules:
- apiGroups: [""]
  resources: ["configmaps", "secrets"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: threatflux-rolebinding
  namespace: threatflux
subjects:
- kind: ServiceAccount
  name: threatflux-sa
  namespace: threatflux
roleRef:
  kind: Role
  name: threatflux-role
  apiGroup: rbac.authorization.k8s.io
```

### ConfigMap and Secrets

```yaml
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: threatflux-config
  namespace: threatflux
data:
  RUST_LOG: "info"
  THREATFLUX_CACHE_SIZE: "100000"
  THREATFLUX_WORKERS: "4"
  THREATFLUX_MAX_FILE_SIZE: "1073741824"  # 1GB
---
apiVersion: v1
kind: Secret
metadata:
  name: threatflux-secrets
  namespace: threatflux
type: Opaque
data:
  api-key: <base64-encoded-api-key>
  db-password: <base64-encoded-db-password>
```

### Deployment

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: threatflux-deployment
  namespace: threatflux
  labels:
    app: threatflux
spec:
  replicas: 3
  selector:
    matchLabels:
      app: threatflux
  template:
    metadata:
      labels:
        app: threatflux
    spec:
      serviceAccountName: threatflux-sa
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 1000
      containers:
      - name: threatflux
        image: threatflux/file-scanner:latest
        imagePullPolicy: Always
        ports:
        - containerPort: 8080
          name: http
        env:
        - name: RUST_LOG
          valueFrom:
            configMapKeyRef:
              name: threatflux-config
              key: RUST_LOG
        - name: THREATFLUX_CACHE_SIZE
          valueFrom:
            configMapKeyRef:
              name: threatflux-config
              key: THREATFLUX_CACHE_SIZE
        - name: API_KEY
          valueFrom:
            secretKeyRef:
              name: threatflux-secrets
              key: api-key
        resources:
          requests:
            memory: "2Gi"
            cpu: "1000m"
          limits:
            memory: "8Gi"
            cpu: "4000m"
        livenessProbe:
          httpGet:
            path: /health
            port: http
          initialDelaySeconds: 30
          periodSeconds: 30
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /ready
            port: http
          initialDelaySeconds: 5
          periodSeconds: 10
          timeoutSeconds: 3
          failureThreshold: 3
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
        volumeMounts:
        - name: cache-volume
          mountPath: /var/cache/threatflux
        - name: tmp-volume
          mountPath: /tmp
      volumes:
      - name: cache-volume
        persistentVolumeClaim:
          claimName: threatflux-cache-pvc
      - name: tmp-volume
        emptyDir: {}
```

### Service and Ingress

```yaml
# service.yaml
apiVersion: v1
kind: Service
metadata:
  name: threatflux-service
  namespace: threatflux
  labels:
    app: threatflux
spec:
  selector:
    app: threatflux
  ports:
  - name: http
    port: 80
    targetPort: 8080
    protocol: TCP
  type: ClusterIP
---
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: threatflux-ingress
  namespace: threatflux
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/rate-limit: "100"
    nginx.ingress.kubernetes.io/rate-limit-window: "1m"
spec:
  tls:
  - hosts:
    - api.threatflux.com
    secretName: threatflux-tls
  rules:
  - host: api.threatflux.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: threatflux-service
            port:
              number: 80
```

### Persistent Storage

```yaml
# pvc.yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: threatflux-cache-pvc
  namespace: threatflux
spec:
  accessModes:
    - ReadWriteMany
  resources:
    requests:
      storage: 100Gi
  storageClassName: fast-ssd
```

### Horizontal Pod Autoscaler

```yaml
# hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: threatflux-hpa
  namespace: threatflux
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: threatflux-deployment
  minReplicas: 3
  maxReplicas: 20
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
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 10
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 0
      policies:
      - type: Percent
        value: 100
        periodSeconds: 15
      - type: Pods
        value: 4
        periodSeconds: 15
      selectPolicy: Max
```

### Deploy to Kubernetes

```bash
# Apply all configurations
kubectl apply -f namespace.yaml
kubectl apply -f configmap.yaml
kubectl apply -f pvc.yaml
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
kubectl apply -f ingress.yaml
kubectl apply -f hpa.yaml

# Check deployment status
kubectl get pods -n threatflux
kubectl get svc -n threatflux
kubectl get ingress -n threatflux

# Check logs
kubectl logs -f deployment/threatflux-deployment -n threatflux
```

## ☁️ Cloud Platform Deployment

### AWS ECS

```json
{
  "family": "threatflux-task",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "2048",
  "memory": "8192",
  "executionRoleArn": "arn:aws:iam::ACCOUNT:role/ecsTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::ACCOUNT:role/threatfluxTaskRole",
  "containerDefinitions": [
    {
      "name": "threatflux",
      "image": "threatflux/file-scanner:latest",
      "portMappings": [
        {
          "containerPort": 8080,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "RUST_LOG",
          "value": "info"
        },
        {
          "name": "THREATFLUX_CACHE_SIZE",
          "value": "100000"
        }
      ],
      "secrets": [
        {
          "name": "API_KEY",
          "valueFrom": "arn:aws:ssm:region:account:parameter/threatflux/api-key"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/threatflux",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "healthCheck": {
        "command": [
          "CMD-SHELL",
          "curl -f http://localhost:8080/health || exit 1"
        ],
        "interval": 30,
        "timeout": 5,
        "retries": 3,
        "startPeriod": 60
      }
    }
  ]
}
```

### AWS Lambda (Serverless)

```rust
// src/lambda.rs
use lambda_runtime::{service_fn, Error, LambdaEvent};
use serde::{Deserialize, Serialize};
use threatflux_hashing::calculate_all_hashes;

#[derive(Deserialize)]
struct Request {
    file_url: String,
}

#[derive(Serialize)]
struct Response {
    hashes: HashMap<String, String>,
}

async fn function_handler(event: LambdaEvent<Request>) -> Result<Response, Error> {
    // Download file from S3
    let file_content = download_from_s3(&event.payload.file_url).await?;
    
    // Perform analysis
    let hashes = calculate_all_hashes(&file_content).await?;
    
    Ok(Response {
        hashes: HashMap::from([
            ("md5".to_string(), hashes.md5),
            ("sha256".to_string(), hashes.sha256),
            ("blake3".to_string(), hashes.blake3),
        ]),
    })
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    lambda_runtime::run(service_fn(function_handler)).await
}
```

### Google Cloud Run

```yaml
# service.yaml
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: threatflux-service
  annotations:
    run.googleapis.com/ingress: all
spec:
  template:
    metadata:
      annotations:
        autoscaling.knative.dev/minScale: "1"
        autoscaling.knative.dev/maxScale: "100"
        run.googleapis.com/cpu-throttling: "false"
        run.googleapis.com/execution-environment: gen2
    spec:
      containerConcurrency: 10
      containers:
      - image: gcr.io/PROJECT-ID/threatflux:latest
        ports:
        - containerPort: 8080
        env:
        - name: RUST_LOG
          value: "info"
        - name: THREATFLUX_CACHE_SIZE
          value: "100000"
        resources:
          limits:
            cpu: "4"
            memory: "8Gi"
        livenessProbe:
          httpGet:
            path: /health
        startupProbe:
          httpGet:
            path: /ready
          initialDelaySeconds: 10
          periodSeconds: 5
          failureThreshold: 10
```

## ⚙️ Configuration Management

### Environment Variables

```bash
# Core Configuration
export RUST_LOG=info
export RUST_BACKTRACE=1

# ThreatFlux Configuration
export THREATFLUX_CACHE_DIR=/var/cache/threatflux
export THREATFLUX_CACHE_SIZE=100000
export THREATFLUX_WORKERS=4
export THREATFLUX_MAX_FILE_SIZE=1073741824  # 1GB

# Library-specific Configuration
export THREATFLUX_HASHING_BUFFER_SIZE=65536
export THREATFLUX_STRINGS_MAX_LENGTH=10000
export THREATFLUX_BINARY_TIMEOUT=300

# Security Configuration
export THREATFLUX_API_KEY_FILE=/etc/threatflux/api-key
export THREATFLUX_TLS_CERT=/etc/threatflux/tls.crt
export THREATFLUX_TLS_KEY=/etc/threatflux/tls.key

# Database Configuration
export DATABASE_URL=postgresql://user:pass@host:5432/threatflux
export REDIS_URL=redis://localhost:6379

# Monitoring Configuration
export PROMETHEUS_ENDPOINT=http://prometheus:9090
export JAEGER_ENDPOINT=http://jaeger:14268/api/traces
```

### Configuration File

```yaml
# /etc/threatflux/config.yaml
server:
  host: "0.0.0.0"
  port: 8080
  workers: 4
  max_connections: 1000
  timeout: 300s

cache:
  backend: "filesystem"
  directory: "/var/cache/threatflux"
  max_size: 100000
  eviction_policy: "lru"
  ttl: 3600s

libraries:
  hashing:
    buffer_size: 65536
    algorithms:
      blake3: true
      sha256: true
      sha512: false
      md5: false
    
  strings:
    min_length: 4
    max_strings: 10000
    max_file_size: 104857600  # 100MB
    
  binary:
    timeout: 300s
    max_sections: 1000
    use_memory_mapping: true

security:
  api_key_file: "/etc/threatflux/api-key"
  rate_limit: 100
  rate_window: "1m"
  max_file_size: 1073741824  # 1GB

logging:
  level: "info"
  format: "json"
  output: "/var/log/threatflux/app.log"
  rotation: "daily"
  max_files: 30

monitoring:
  metrics_enabled: true
  metrics_port: 9090
  tracing_enabled: true
  jaeger_endpoint: "http://jaeger:14268/api/traces"
```

## 📊 Monitoring & Observability

### Prometheus Metrics

```rust
// src/metrics.rs
use prometheus::{
    Counter, Histogram, Gauge, Registry,
    register_counter, register_histogram, register_gauge,
};

lazy_static! {
    pub static ref ANALYSIS_REQUESTS_TOTAL: Counter = register_counter!(
        "threatflux_analysis_requests_total",
        "Total number of analysis requests"
    ).unwrap();
    
    pub static ref ANALYSIS_DURATION_SECONDS: Histogram = register_histogram!(
        "threatflux_analysis_duration_seconds",
        "Time spent on file analysis"
    ).unwrap();
    
    pub static ref CACHE_HIT_RATIO: Gauge = register_gauge!(
        "threatflux_cache_hit_ratio",
        "Cache hit ratio"
    ).unwrap();
    
    pub static ref ACTIVE_ANALYSES: Gauge = register_gauge!(
        "threatflux_active_analyses",
        "Number of currently active analyses"
    ).unwrap();
}
```

### Grafana Dashboard

```json
{
  "dashboard": {
    "title": "ThreatFlux Monitoring",
    "panels": [
      {
        "title": "Request Rate",
        "type": "stat",
        "targets": [
          {
            "expr": "rate(threatflux_analysis_requests_total[5m])",
            "legendFormat": "Requests/sec"
          }
        ]
      },
      {
        "title": "Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(threatflux_analysis_duration_seconds_bucket[5m]))",
            "legendFormat": "95th percentile"
          },
          {
            "expr": "histogram_quantile(0.50, rate(threatflux_analysis_duration_seconds_bucket[5m]))",
            "legendFormat": "50th percentile"
          }
        ]
      },
      {
        "title": "Cache Performance",
        "type": "stat",
        "targets": [
          {
            "expr": "threatflux_cache_hit_ratio",
            "legendFormat": "Hit Ratio"
          }
        ]
      }
    ]
  }
}
```

### Logging Configuration

```yaml
# fluent-bit.conf
[SERVICE]
    Flush         1
    Log_Level     info
    Daemon        off
    Parsers_File  parsers.conf

[INPUT]
    Name              tail
    Path              /var/log/threatflux/*.log
    Parser            json
    Tag               threatflux.*
    Refresh_Interval  5

[OUTPUT]
    Name  es
    Match *
    Host  elasticsearch
    Port  9200
    Index threatflux-logs
    Type  _doc
```

## 💾 Backup & Recovery

### Database Backup

```bash
#!/bin/bash
# backup.sh

BACKUP_DIR="/var/backups/threatflux"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# PostgreSQL backup
pg_dump -h $DB_HOST -U $DB_USER threatflux > \
    "$BACKUP_DIR/db_backup_$TIMESTAMP.sql"

# Redis backup
redis-cli --rdb "$BACKUP_DIR/redis_backup_$TIMESTAMP.rdb"

# Cache directory backup
tar -czf "$BACKUP_DIR/cache_backup_$TIMESTAMP.tar.gz" \
    /var/cache/threatflux

# Upload to S3
aws s3 cp "$BACKUP_DIR/" "s3://threatflux-backups/$(date +%Y/%m/%d)/" \
    --recursive --exclude "*" --include "*$TIMESTAMP*"

# Cleanup old backups (keep 30 days)
find "$BACKUP_DIR" -name "*.sql" -mtime +30 -delete
find "$BACKUP_DIR" -name "*.rdb" -mtime +30 -delete
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +30 -delete
```

### Disaster Recovery

```yaml
# disaster-recovery.yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: threatflux-restore
spec:
  template:
    spec:
      containers:
      - name: restore
        image: threatflux/backup-restore:latest
        env:
        - name: BACKUP_SOURCE
          value: "s3://threatflux-backups/2024/01/15/"
        - name: RESTORE_TARGET
          value: "/var/lib/postgresql/data"
        command:
        - /bin/bash
        - -c
        - |
          # Download latest backup
          aws s3 cp $BACKUP_SOURCE/db_backup_*.sql /tmp/
          
          # Restore database
          psql -h $DB_HOST -U $DB_USER -d threatflux < /tmp/db_backup_*.sql
          
          # Restore cache
          aws s3 cp $BACKUP_SOURCE/cache_backup_*.tar.gz /tmp/
          tar -xzf /tmp/cache_backup_*.tar.gz -C /
      restartPolicy: OnFailure
```

## 📈 Scaling Strategies

### Horizontal Scaling

```yaml
# hpa-advanced.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: threatflux-hpa-advanced
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: threatflux-deployment
  minReplicas: 5
  maxReplicas: 100
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 60
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 70
  - type: Pods
    pods:
      metric:
        name: active_analyses_per_pod
      target:
        type: AverageValue
        averageValue: "10"
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 600
      policies:
      - type: Percent
        value: 25
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
      - type: Percent
        value: 50
        periodSeconds: 30
      - type: Pods
        value: 10
        periodSeconds: 30
```

### Vertical Scaling

```yaml
# vpa.yaml
apiVersion: autoscaling.k8s.io/v1
kind: VerticalPodAutoscaler
metadata:
  name: threatflux-vpa
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: threatflux-deployment
  updatePolicy:
    updateMode: "Auto"
  resourcePolicy:
    containerPolicies:
    - containerName: threatflux
      minAllowed:
        cpu: 500m
        memory: 1Gi
      maxAllowed:
        cpu: 8
        memory: 32Gi
      controlledResources: ["cpu", "memory"]
```

### Multi-Region Deployment

```yaml
# regions.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: region-config
data:
  regions: |
    - name: us-east-1
      clusters:
        - cluster-1
        - cluster-2
    - name: eu-west-1
      clusters:
        - cluster-3
        - cluster-4
    - name: ap-southeast-1
      clusters:
        - cluster-5
        - cluster-6
```

## 🔒 Security Considerations

### Network Security

```yaml
# network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: threatflux-network-policy
spec:
  podSelector:
    matchLabels:
      app: threatflux
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
  - to: []
    ports:
    - protocol: TCP
      port: 443  # HTTPS
    - protocol: TCP
      port: 53   # DNS
    - protocol: UDP
      port: 53   # DNS
```

### Pod Security Policy

```yaml
# psp.yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: threatflux-psp
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    - 'persistentVolumeClaim'
  hostNetwork: false
  hostIPC: false
  hostPID: false
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
```

## 🔧 Troubleshooting

### Common Issues

#### High Memory Usage

```bash
# Check memory usage
kubectl top pods -n threatflux

# Analyze memory allocation
kubectl exec -it <pod-name> -n threatflux -- \
    ps aux --sort=-%mem | head -10

# Check for memory leaks
kubectl logs <pod-name> -n threatflux | grep "memory"
```

**Solutions:**
- Adjust `max_file_size` configuration
- Increase memory limits
- Enable memory profiling
- Check for stuck analyses

#### High CPU Usage

```bash
# Check CPU usage
kubectl top pods -n threatflux

# Profile CPU usage
kubectl exec -it <pod-name> -n threatflux -- \
    top -p $(pgrep file-scanner)
```

**Solutions:**
- Reduce concurrent analyses
- Optimize analysis algorithms
- Scale horizontally
- Check for infinite loops

#### Cache Issues

```bash
# Check cache hit ratio
curl http://localhost:8080/cache/stats

# Clear cache if corrupted
curl -X POST http://localhost:8080/cache/clear
```

**Solutions:**
- Verify cache backend connectivity
- Check disk space for filesystem cache
- Validate cache configuration
- Monitor cache performance metrics

### Diagnostic Commands

```bash
# Check application health
curl http://localhost:8080/health

# Get application metrics
curl http://localhost:8080/metrics

# Check configuration
kubectl get configmap threatflux-config -o yaml

# Check secrets
kubectl get secret threatflux-secrets -o yaml

# Check logs
kubectl logs -f deployment/threatflux-deployment -n threatflux

# Check events
kubectl get events -n threatflux --sort-by='.lastTimestamp'

# Check resource usage
kubectl describe pod <pod-name> -n threatflux
```

### Performance Troubleshooting

```bash
# Profile application
kubectl exec -it <pod-name> -n threatflux -- \
    perf record -g ./file-scanner analyze test-file.bin

# Memory profiling
kubectl exec -it <pod-name> -n threatflux -- \
    valgrind --tool=massif ./file-scanner analyze test-file.bin

# Network troubleshooting
kubectl exec -it <pod-name> -n threatflux -- \
    netstat -tuln

# Disk I/O analysis
kubectl exec -it <pod-name> -n threatflux -- \
    iostat -x 1
```

## 📋 Deployment Checklist

### Pre-Deployment
- [ ] Review system requirements
- [ ] Verify network connectivity
- [ ] Install dependencies
- [ ] Configure storage
- [ ] Set up monitoring
- [ ] Review security settings
- [ ] Prepare backup strategy

### Deployment
- [ ] Build application
- [ ] Create container images
- [ ] Deploy infrastructure
- [ ] Apply configurations
- [ ] Start services
- [ ] Verify health checks
- [ ] Test functionality

### Post-Deployment
- [ ] Monitor performance
- [ ] Check logs for errors
- [ ] Verify metrics collection
- [ ] Test backup procedures
- [ ] Document configuration
- [ ] Train operations team
- [ ] Set up alerting

### Maintenance
- [ ] Regular security updates
- [ ] Performance optimization
- [ ] Capacity planning
- [ ] Backup verification
- [ ] Disaster recovery testing
- [ ] Documentation updates

This deployment guide provides comprehensive instructions for various deployment scenarios. Choose the approach that best fits your infrastructure and requirements. Always test deployments in a staging environment before deploying to production.
