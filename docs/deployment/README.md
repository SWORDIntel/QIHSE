# QIHSE Deployment Guide

> **Source entry points, not verified deployment evidence:**
> - Build: `./scripts/build-native.sh --auto` per machine — auto-detects every
>   SIMD ISA and `make all` runs the mandatory host-ISA verification.
> - Cluster install: `scripts/install_qihse.sh` (provisions keys/config, systemd
>   units, health checks; this mutates live deployment state).
> - Rolling binary updates: `scripts/cluster_rolling_restart.sh` is an entry
>   point to review, not proof of rolling compatibility or current health.
>   Apply the staged upgrade gates below before any activation.
> - Replication: `scripts/cluster_replica_deploy.sh` (read-only QKP-pinned
>   replica units, one namespace each).
> - Operator access on hardened nodes: `qihse-admin-cli` (pinned QKP admin
>   identity). See [OPERATIONS.md](../OPERATIONS.md) and
>   [manual/deployment/README.md](../manual/deployment/README.md).
>
> **Status: partial — status unverified.** The sections below are a legacy
deployment guide that predates the
> federation and mTLS work; cluster and TLS guidance should be checked against
> [architecture/federation_overview.md](../architecture/federation_overview.md)
> and the [API reference](../API_REFERENCE.md).
>
> **Code samples that will not compile.** The tuning snippets below call
> `qihse_memory_configure()`, `qihse_backend_optimize()` and
> `qihse_ml_tune_engine()`, none of which is declared in any header under
> `include/` or defined anywhere in the tree. They are illustrative, not a
> current interface; use [API_REFERENCE.md](../API_REFERENCE.md) for the
> surfaces that exist.
>
> **Repository rule violation:** this document contains absolute paths.
> `AGENTS.md` requires strictly relative or dynamically resolved paths.

The legacy examples below are not a production cutover runbook. No current
source/deployed hash parity, leader identity, rollout or recovery was verified
in this documentation update.

## Staged upgrade prerequisites

Follow [Operations §1.6](../OPERATIONS.md#16-staged-installation-and-upgrade-gates)
for staging with `DESTDIR`, exact artifact manifests, all installed-library
consumers, pre-upgrade recovery images and authenticated health gates. A dirty
shared checkout is not a release artifact; identical directory names are not
hash parity. Do not run `sudo make install`, provisioning scripts or rolling
restart scripts merely to try a development build. Leadership/quorum must be
established from current authenticated observations; unknown leadership blocks
a rolling change. PING/systemd status alone does not establish data health.

SQL English FTS dynamically loads `libstemmer.so.0d` (Debian/Ubuntu
`libstemmer0d`) in each actual service/chroot/container runtime. It is bounded
ASCII English/Snowball (4096-byte input/output, 256-byte tokens), not complete
PostgreSQL text search. Missing dependency/symbols, unsupported non-ASCII or
oversized input fail closed; even empty input needs the dependency.

## Table of Contents

1. [Deployment Planning](#deployment-planning)
2. [Single-Node Deployment](#single-node-deployment)
3. [Multi-Node Cluster Deployment](#multi-node-cluster-deployment)
4. [Cloud Deployment](#cloud-deployment)
5. [Monitoring and Observability](#monitoring-and-observability)
6. [Backup and Recovery](#backup-and-recovery)
7. [Security Hardening](#security-hardening)
8. [Performance Optimization](#performance-optimization)

## Deployment Planning

### Capacity Planning

#### Hardware Requirements

**Minimum Production Requirements:**
- **CPU**: Intel Xeon or Core i7 with AVX2 (8 cores, 16 threads)
- **RAM**: 32GB DDR4
- **Storage**: 500GB NVMe SSD
- **Network**: 10Gbps Ethernet

**Recommended Production Requirements:**
- **CPU**: Intel Xeon Scalable with AVX-512/AVX-VNNI/AMX (16+ cores)
- **RAM**: 128GB+ DDR4/DDR5
- **Storage**: 2TB+ NVMe SSD (RAID 1/10)
- **Network**: 25Gbps+ Ethernet or Infiniband
- **GPU**: NVIDIA A100/H100 or Intel Data Center GPU (optional)
- **NPU**: Intel Xeon with integrated NPU (optional)

#### Workload Sizing

| Workload Type | Dataset Size | QPS Target | Memory Required | Storage Required |
|---------------|--------------|------------|-----------------|------------------|
| Vector Search (SIFT1M) | 1M vectors | 10K | 8GB | 500MB |
| Vector Search (Deep1B) | 1B vectors | 50K | 256GB | 2TB |
| Graph Search (LiveJournal) | 4M nodes | 1K | 16GB | 1GB |
| Graph Search (Freebase) | 100M nodes | 5K | 128GB | 50GB |
| Constraint (TSP 1K) | 1K cities | 100 | 4GB | 100MB |

### Network Architecture

#### Single Node
```
┌─────────────────┐
│   Application   │
│   ┌─────────┐   │
│   │  QIHSE  │   │
│   │ Engine  │   │
│   └─────────┘   │
│                 │
│  Hardware:      │
│  CPU + GPU/NPU  │
└─────────────────┘
```

#### Multi-Node Cluster
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Node 1    │    │   Node 2    │    │   Node 3    │
│ ┌─────────┐ │    │ ┌─────────┐ │    │ ┌─────────┐ │
│ │ QIHSE   │◄┼───►│ │ QIHSE   │◄┼───►│ │ QIHSE   │ │
│ │ Engine  │ │    │ │ Engine  │ │    │ │ Engine  │ │
│ └─────────┘ │    │ └─────────┘ │    │ └─────────┘ │
│             │    │             │    │             │
│ Coordinator │    │   Worker    │    │   Worker    │
└─────────────┘    └─────────────┘    └─────────────┘
       │                    │                    │
       └────────────────────┼────────────────────┘
                            │
                    ┌─────────────┐
                    │ Load Balancer│
                    │   (Nginx)   │
                    └─────────────┘
```

### Security Architecture

```
┌─────────────────────────────────────────────────┐
│                External Network                 │
├─────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────┐  │
│  │  Load       │  │  API        │  │  Auth   │  │
│  │  Balancer   │  │  Gateway    │  │ Service │  │
│  │  (TLS)      │  │  (mTLS)     │  │         │  │
│  └─────────────┘  └─────────────┘  └─────────┘  │
├─────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────┐  │
│  │  QIHSE      │  │  Security   │  │  Audit  │  │
│  │  Engine     │  │  Module     │  │ Service │  │
│  │             │  │  (CNSA2*)   │  │         │  │
│  └─────────────┘  └─────────────┘  └─────────┘  │
├─────────────────────────────────────────────────┤
│                Internal Network                 │
├─────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────┐  │
│  │  Monitoring │  │  Logging    │  │  Backup │  │
│  │  Stack      │  │  System     │  │ Service │  │
│  └─────────────┘  └─────────────┘  └─────────┘  │
└─────────────────────────────────────────────────┘
```

## Single-Node Deployment

### Basic Installation

```bash
# Install system dependencies
sudo apt update
sudo apt install -y build-essential cmake libssl-dev libnuma-dev libstemmer0d

# Install Intel OneAPI
wget -O- https://apt.repos.intel.com/intel-gpg-keys/GPG-PUB-KEY-INTEL-SW-PRODUCTS.PUB \
| gpg --dearmor | sudo tee /usr/share/keyrings/oneapi-archive-keyring.gpg > /dev/null

echo "deb [signed-by=/usr/share/keyrings/oneapi-archive-keyring.gpg] https://apt.repos.intel.com/oneapi all main" \
| sudo tee /etc/apt/sources.list.d/oneAPI.list

sudo apt update
sudo apt install -y intel-oneapi-basekit

# Install OpenVINO for NPU support
sudo apt install -y libopenvino-dev

# Build QIHSE
git clone <repository-url>
cd qihse-breakthroughalgo
make all
# Stage only; activation needs the gates above.
STAGE="$(mktemp -d)"
make install DESTDIR="$STAGE" PREFIX=/usr/local
```

### Configuration for Production

```json
{
  "hardware": {
    "cpu": {
      "avx2": true,
      "avx512": true,
      "amx": true
    },
    "npu": {
      "openvino": true,
      "pim_operations": true
    }
  },
  "quantum": {
    "mode": "hybrid",
    "rff_dimension": 4096,
    "rff_gamma": 1.0
  },
  "verification": {
    "mode": "precision",
    "confidence_threshold": 0.95,
    "max_verification_time_ms": 1000
  },
  "memory": {
    "max_memory_mb": 32768,
    "enable_uma": true,
    "memory_policy": "performance"
  },
  "ml": {
    "enable_self_optimization": true,
    "batch_size": 128,
    "learning_rate": 0.001
  },
  "energy": {
    "enable_energy_aware": true,
    "max_power_watts": 200,
    "thermal_limit_celsius": 80.0
  },
  "security": {
    "level": "cnsa2",
    "key_store_path": "/etc/qihse/keys"
  },
  "logging": {
    "level": "info",
    "file": "/var/log/qihse/qihse.log",
    "max_size_mb": 100,
    "max_files": 10
  },
  "monitoring": {
    "enable_prometheus": true,
    "prometheus_port": 9090,
    "enable_health_checks": true,
    "health_check_port": 8080
  }
}
```

### Systemd Service

```bash
# Create system user
sudo useradd -r -s /bin/false qihse

# Create directories
sudo mkdir -p /etc/qihse /var/lib/qihse /var/log/qihse
sudo chown qihse:qihse /var/lib/qihse /var/log/qihse

# Create systemd service
sudo tee /etc/systemd/system/qihse.service > /dev/null <<EOF
[Unit]
Description=QIHSE Search Engine
After=network.target
Requires=network.target

[Service]
Type=simple
User=qihse
Group=qihse
Environment=QIHSE_CONFIG=/etc/qihse/config.json
Environment=QIHSE_DATA_DIR=/var/lib/qihse
Environment=QIHSE_LOG_DIR=/var/log/qihse
ExecStart=/usr/local/bin/qihse-server --config /etc/qihse/config.json
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable qihse
sudo systemctl start qihse
sudo systemctl status qihse
```

### Log Rotation

```bash
# Create logrotate configuration
sudo tee /etc/logrotate.d/qihse > /dev/null <<EOF
/var/log/qihse/*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 644 qihse qihse
    postrotate
        systemctl reload qihse
    endscript
}
EOF
```

## Multi-Node Cluster Deployment

### Cluster Architecture

**Coordinator Node:**
- Manages cluster membership
- Coordinates distributed operations
- Handles load balancing
- Maintains global state

**Worker Nodes:**
- Execute search operations
- Participate in distributed algorithms
- Maintain local state
- Report health and metrics

### Configuration for Clustering

**Coordinator Configuration:**
```json
{
  "node": {
    "id": 1,
    "role": "coordinator",
    "hostname": "qihse-coord-01",
    "port": 8080
  },
  "cluster": {
    "name": "production-cluster",
    "expected_nodes": 8,
    "heartbeat_interval_ms": 1000,
    "failure_timeout_ms": 5000
  },
  "distributed": {
    "enable_distributed": true,
    "coordinator_mode": true,
    "replication_factor": 3,
    "consistency_level": "quorum"
  }
}
```

**Worker Configuration:**
```json
{
  "node": {
    "id": 2,
    "role": "worker",
    "hostname": "qihse-worker-01",
    "port": 8080,
    "coordinator_host": "qihse-coord-01",
    "coordinator_port": 8080
  },
  "distributed": {
    "enable_distributed": true,
    "coordinator_mode": false,
    "local_shard_count": 4
  }
}
```

### Docker Compose for Development

```yaml
version: '3.8'
services:
  qihse-coordinator:
    image: qihse:latest
    environment:
      - QIHSE_NODE_ROLE=coordinator
      - QIHSE_NODE_ID=1
      - QIHSE_CLUSTER_NAME=dev-cluster
    ports:
      - "8080:8080"
    volumes:
      - ./config/coordinator.json:/etc/qihse/config.json
      - ./data:/var/lib/qihse
      - ./logs:/var/log/qihse

  qihse-worker-1:
    image: qihse:latest
    environment:
      - QIHSE_NODE_ROLE=worker
      - QIHSE_NODE_ID=2
      - QIHSE_COORDINATOR_HOST=qihse-coordinator
      - QIHSE_COORDINATOR_PORT=8080
    volumes:
      - ./config/worker.json:/etc/qihse/config.json
      - ./data:/var/lib/qihse
      - ./logs:/var/log/qihse
    depends_on:
      - qihse-coordinator

  qihse-worker-2:
    image: qihse:latest
    environment:
      - QIHSE_NODE_ROLE=worker
      - QIHSE_NODE_ID=3
      - QIHSE_COORDINATOR_HOST=qihse-coordinator
      - QIHSE_COORDINATOR_PORT=8080
    volumes:
      - ./config/worker.json:/etc/qihse/config.json
      - ./data:/var/lib/qihse
      - ./logs:/var/log/qihse
    depends_on:
      - qihse-coordinator
```

### Kubernetes Deployment

**Coordinator Deployment:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: qihse-coordinator
spec:
  replicas: 1
  selector:
    matchLabels:
      app: qihse
      role: coordinator
  template:
    metadata:
      labels:
        app: qihse
        role: coordinator
    spec:
      containers:
      - name: qihse
        image: qihse:latest
        ports:
        - containerPort: 8080
        env:
        - name: QIHSE_NODE_ROLE
          value: "coordinator"
        - name: QIHSE_NODE_ID
          value: "1"
        volumeMounts:
        - name: config
          mountPath: /etc/qihse
        - name: data
          mountPath: /var/lib/qihse
        - name: logs
          mountPath: /var/log/qihse
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: config
        configMap:
          name: qihse-config
      - name: data
        persistentVolumeClaim:
          claimName: qihse-data
      - name: logs
        emptyDir: {}
```

**Worker Deployment:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: qihse-worker
spec:
  replicas: 5
  selector:
    matchLabels:
      app: qihse
      role: worker
  template:
    metadata:
      labels:
        app: qihse
        role: worker
    spec:
      containers:
      - name: qihse
        image: qihse:latest
        ports:
        - containerPort: 8080
        env:
        - name: QIHSE_NODE_ROLE
          value: "worker"
        - name: QIHSE_COORDINATOR_HOST
          value: "qihse-coordinator"
        resources:
          requests:
            memory: "32Gi"
            cpu: "8"
          limits:
            memory: "64Gi"
            cpu: "16"
        volumeMounts:
        - name: config
          mountPath: /etc/qihse
        - name: data
          mountPath: /var/lib/qihse
      volumes:
      - name: config
        configMap:
          name: qihse-config
      - name: data
        emptyDir: {}
```

**Load Balancer Service:**
```yaml
apiVersion: v1
kind: Service
metadata:
  name: qihse-lb
spec:
  type: LoadBalancer
  ports:
  - port: 80
    targetPort: 8080
  selector:
    app: qihse
    role: coordinator
```

## Cloud Deployment

### AWS Deployment

**EC2 Instance Configuration:**
```terraform
resource "aws_instance" "qihse_node" {
  ami           = "ami-0abcdef1234567890"  # Ubuntu 22.04 with AVX-512
  instance_type = "c6i.16xlarge"          # 32 vCPUs, AVX-512 support

  root_block_device {
    volume_size = 500
    volume_type = "gp3"
    iops        = 16000
  }

  tags = {
    Name = "qihse-node"
  }
}

resource "aws_launch_template" "qihse_worker" {
  name_prefix   = "qihse-worker-"
  image_id      = "ami-0abcdef1234567890"
  instance_type = "c6i.8xlarge"

  block_device_mappings {
    device_name = "/dev/sda1"
    ebs {
      volume_size = 200
      volume_type = "gp3"
    }
  }

  user_data = base64encode(<<EOF
#!/bin/bash
# Install QIHSE and join cluster
wget https://qihse-releases.s3.amazonaws.com/qihse_latest.deb
dpkg -i qihse_latest.deb
systemctl enable qihse
systemctl start qihse
EOF
  )
}
```

**Auto Scaling Group:**
```terraform
resource "aws_autoscaling_group" "qihse_workers" {
  name                = "qihse-workers"
  max_size            = 20
  min_size            = 3
  desired_capacity    = 8
  launch_template     = aws_launch_template.qihse_worker.id

  tag {
    key                 = "Name"
    value               = "qihse-worker"
    propagate_at_launch = true
  }

  tag {
    key                 = "Role"
    value               = "worker"
    propagate_at_launch = true
  }
}
```

### Azure Deployment

**VM Scale Set:**
```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "vmSku": {
      "type": "string",
      "defaultValue": "Standard_D16s_v5",
      "metadata": {
        "description": "VM size with AVX-512 support"
      }
    },
    "instanceCount": {
      "type": "int",
      "defaultValue": 3,
      "metadata": {
        "description": "Number of VM instances"
      }
    }
  },
  "resources": [
    {
      "type": "Microsoft.Compute/virtualMachineScaleSets",
      "apiVersion": "2022-08-01",
      "name": "qihse-scale-set",
      "location": "[resourceGroup().location]",
      "sku": {
        "name": "[parameters('vmSku')]",
        "tier": "Standard",
        "capacity": "[parameters('instanceCount')]"
      },
      "properties": {
        "overprovision": false,
        "upgradePolicy": {
          "mode": "Manual"
        },
        "virtualMachineProfile": {
          "storageProfile": {
            "imageReference": {
              "publisher": "Canonical",
              "offer": "0001-com-ubuntu-server-jammy",
              "sku": "22_04-lts",
              "version": "latest"
            },
            "osDisk": {
              "caching": "ReadWrite",
              "createOption": "FromImage",
              "managedDisk": {
                "storageAccountType": "Premium_LRS"
              }
            }
          },
          "osProfile": {
            "computerNamePrefix": "qihse",
            "adminUsername": "azureuser",
            "linuxConfiguration": {
              "disablePasswordAuthentication": true,
              "ssh": {
                "publicKeys": [
                  {
                    "path": "/home/azureuser/.ssh/authorized_keys",
                    "keyData": "[parameters('sshPublicKey')]"
                  }
                ]
              }
            }
          },
          "extensionProfile": {
            "extensions": [
              {
                "name": "qihse-install",
                "properties": {
                  "publisher": "Microsoft.Azure.Extensions",
                  "type": "CustomScript",
                  "typeHandlerVersion": "2.1",
                  "settings": {
                    "commandToExecute": "wget https://qihse-releases.blob.core.windows.net/qihse_latest.deb && dpkg -i qihse_latest.deb && systemctl enable qihse && systemctl start qihse"
                  }
                }
              }
            ]
          }
        }
      }
    }
  ]
}
```

## Monitoring and Observability

### Prometheus Metrics

```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'qihse'
    static_configs:
      - targets: ['qihse-node-1:9090', 'qihse-node-2:9090']
    metrics_path: '/metrics'
    scrape_interval: 5s
```

### Grafana Dashboards

**Key Metrics to Monitor:**
- **Performance**: QPS, latency percentiles, throughput
- **Resource Usage**: CPU, memory, disk I/O, network
- **Error Rates**: Search failures, verification failures, timeouts
- **Hardware**: Temperature, power consumption, hardware errors
- **Distributed**: Node health, cluster coherence, message latency

```json
{
  "dashboard": {
    "title": "QIHSE Cluster Overview",
    "panels": [
      {
        "title": "Query Performance",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(qihse_queries_total[5m])",
            "legendFormat": "QPS"
          },
          {
            "expr": "histogram_quantile(0.95, rate(qihse_query_duration_seconds_bucket[5m]))",
            "legendFormat": "P95 Latency"
          }
        ]
      },
      {
        "title": "Resource Usage",
        "type": "bargauge",
        "targets": [
          {
            "expr": "qihse_cpu_usage_percent",
            "legendFormat": "CPU Usage %"
          },
          {
            "expr": "qihse_memory_usage_bytes / qihse_memory_total_bytes * 100",
            "legendFormat": "Memory Usage %"
          }
        ]
      }
    ]
  }
}
```

### Alerting Rules

```yaml
# alert_rules.yml
groups:
  - name: qihse
    rules:
      - alert: HighQueryLatency
        expr: histogram_quantile(0.95, rate(qihse_query_duration_seconds_bucket[5m])) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High query latency detected"
          description: "95th percentile query latency is {{ $value }}s"

      - alert: NodeDown
        expr: up{job="qihse"} == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "QIHSE node is down"
          description: "QIHSE node {{ $labels.instance }} has been down for 5 minutes"

      - alert: HighErrorRate
        expr: rate(qihse_errors_total[5m]) / rate(qihse_queries_total[5m]) > 0.05
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High error rate detected"
          description: "Error rate is {{ $value | humanizePercentage }}"
```

## Backup and Recovery

### Preserve a recoverable generation

Do not recursively copy a live data directory and call it a consistent backup,
or overlay an archive onto a populated live store. Do not delete retained
backups merely because upload or service startup succeeded.

For the bounded SQL store, use the authenticated
`qihse_table_store_backup()` / `qihse_table_store_restore()` APIs described in
[transactions/MVCC](../architecture/transactions_mvcc.md#durable-formats-and-offline-transfer).
They require an active bootstrap-system Operator (user/tenant ID 0), private
owner-only parent directories and fresh nonexisting destination paths. Backup
captures only committed catalog/rows/retry receipts from an open, unpoisoned
durable store; restore requires exclusive access to both source and target.
Transfer accepts validated store v3–v5 images only, despite general store
read compatibility with v1–v5. Current writes use store v5/schema v4; old-format
read support does **not** imply binary downgrade support or conversion.

For other engines and service state, use their supported consistent snapshot
mechanism or quiesce all writers and take an offline, complete generation.
Inventory configuration, auth provisioning, trust pins/keys, audit/WAL files,
models and external dependencies separately; the SQL transfer APIs do not
capture them. Keep secrets under existing ownership/access controls, encrypt
and integrity-protect archives, and record the data generation, exact runtime
hashes and dependency manifest. Verify off-host retrieval before retention
decisions. No service-wide backup schedule is established by these examples.

### Isolated recovery and activation gates

1. Preserve the original data, evidence and last known-good runtime. Choose
   operator-configured `BACKUP_ROOT` and `RECOVERY_ROOT` outside live data and
   stage private recovery directories; never restore over an active ledger.
2. Validate archive provenance, hashes and permissions. Restore into a fresh
   isolated target with compatible code and runtime dependencies. Keep the
   source and target closed elsewhere; never remove lock files to bypass
   exclusion. A failed transfer may have published an image before an fsync
   error: preserve and inspect it rather than assuming nothing happened.
3. Reopen/restart the isolated target and check catalog/row consistency,
   retry receipts and lost-reply behavior, expected reads/writes, audit
   continuity, TLS/auth and low-clearance denial. Check all relevant engines
   and clients; service status alone is not evidence of recovery.
4. Test any older-runtime rollback against the preserved **pre-upgrade** image,
   not data newly written by the candidate. Account explicitly for writes after
   that backup; do not silently discard them or replay ambiguous commits.
5. Only after isolated checks and current leadership/quorum/replication health
   pass, use the reviewed activation plan. Unknown leadership blocks a cluster
   restore/rollout; do not force promotion or restart several members blindly.
   Recheck application behavior and durable commit/audit progress after each
   activation. Retain originals until recovery is independently accepted.

This is a required validation procedure, not a claim of a successful live restore.

## Security Hardening

### CNSA 2.0 Alignment (In Progress)

> **Note:** QIHSE targets CNSA 2.0 alignment but has not completed formal compliance certification. Transport encryption (ChaCha20-Poly1305 AEAD) is implemented and opt-in via ctx->tls_ctx; cleartext is the default.

**Key Management:**
```bash
# Initialize HSM for key storage
qihse-security --init-hsm --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so

# Generate CNSA 2.0 aligned keys
qihse-security --generate-key --algorithm ecdsa-p384 --key-id master-key

# Configure key rotation
qihse-security --set-rotation-policy --key-id master-key --interval 90d
```

**Secure Configuration:**
```json
{
  "security": {
    "level": "cnsa2",
    "encryption": {
      "algorithm": "aes-256-gcm",
      "key_rotation_days": 90,
      "hsm_required": true
    },
    "authentication": {
      "method": "certificate",
      "ca_cert": "/etc/qihse/certs/ca.pem",
      "client_cert_required": true
    },
    "audit": {
      "enabled": true,
      "log_security_events": true,
      "integrity_check": true
    }
  }
}
```

### Network Security

**Firewall Configuration:**
```bash
# UFW configuration for QIHSE
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 8080/tcp  # QIHSE API
sudo ufw allow 9090/tcp  # Prometheus metrics
sudo ufw --force enable
```

**TLS Configuration:**
```nginx
# Nginx configuration for TLS termination
server {
    listen 443 ssl http2;
    server_name qihse.example.com;

    ssl_certificate /etc/ssl/certs/qihse.pem;
    ssl_certificate_key /etc/ssl/private/qihse.key;
    ssl_protocols TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Performance Optimization

### Hardware Tuning

**CPU Configuration:**
```bash
# Disable CPU frequency scaling for consistent performance
sudo cpupower frequency-set -g performance

# Set CPU governor to performance
echo 'GOVERNOR="performance"' | sudo tee /etc/default/cpufrequtils
sudo systemctl restart cpufrequtils

# Configure huge pages for better memory performance
echo 1024 | sudo tee /proc/sys/vm/nr_hugepages
```

**Memory Configuration:**
```bash
# Configure transparent huge pages
echo always | sudo tee /sys/kernel/mm/transparent_hugepage/enabled
echo always | sudo tee /sys/kernel/mm/transparent_hugepage/defrag

# Increase maximum memory map areas
echo 262144 | sudo tee /proc/sys/vm/max_map_count
```

**Storage Optimization:**
```bash
# Optimize I/O scheduler for NVMe
echo none | sudo tee /sys/block/nvme0n1/queue/scheduler

# Increase I/O request queue depth
echo 256 | sudo tee /sys/block/nvme0n1/queue/nr_requests

# Enable disk writeback caching
sudo hdparm -W 1 /dev/nvme0n1
```

### QIHSE-Specific Tuning

**Memory Pool Configuration:**
```c
// Configure memory pools for different workloads
qihse_memory_config_t mem_config = {
    .vector_pool_size_mb = 4096,
    .graph_pool_size_mb = 2048,
    .quantum_pool_size_mb = 8192,
    .enable_memory_prefetch = true,
    .prefetch_distance = 4
};

qihse_memory_configure(&mem_config);
```

**Backend Optimization:**
```c
// Optimize backend selection based on workload
qihse_backend_optimize_t opt_config = {
    .workload_type = QIHSE_WORKLOAD_VECTOR_SEARCH,
    .target_qps = 15000,
    .max_latency_ms = 10,
    .energy_budget_watts = 200,
    .thermal_limit_celsius = 75.0
};

qihse_backend_optimize(&opt_config);
```

**ML Engine Tuning:**
```c
// Configure ML engine for production
qihse_ml_tune_config_t ml_config = {
    .learning_rate = 0.001,
    .batch_size = 256,
    .gradient_clip = 1.0,
    .weight_decay = 0.0001,
    .enable_mixed_precision = true,
    .enable_gradient_checkpointing = true
};

qihse_ml_tune_engine(&ml_config);
```

### Benchmarking and Profiling

```bash
# Run comprehensive benchmark suite
qihse-benchmark --suite comprehensive --output benchmark_results.json

# Profile application performance
qihse-profile --config production.json --duration 300 --output profile_data.json

# Generate optimization recommendations
qihse-optimize --benchmark benchmark_results.json --profile profile_data.json --output recommendations.json
```

---

This deployment guide provides comprehensive instructions for production deployment of QIHSE across various environments. For additional support, consult the [User Guide](../manual/user/README.md) or the [Security Guide](../security/README.md).
