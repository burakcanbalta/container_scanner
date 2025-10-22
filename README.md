# 🐳 Container Security Scanner

A comprehensive container security assessment tool designed for DevOps and security teams. Automatically scan running Docker containers for security misconfigurations, vulnerabilities, and compliance issues with real-time risk scoring and reporting.

---

## 🚀 Quick Start

### Prerequisites

```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install Trivy for vulnerability scanning
wget https://github.com/aquasecurity/trivy/releases/download/v0.45.1/trivy_0.45.1_Linux-64bit.tar.gz
tar -xzf trivy_0.45.1_Linux-64bit.tar.gz
sudo mv trivy /usr/local/bin/
```

### Installation & Setup

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/ContainerSecurityScanner.git
cd ContainerSecurityScanner

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run security scan
python container_scanner.py --scan

# 4. Generate report
python container_scanner.py --report --format json
```

### Basic Usage

```bash
# Scan all running containers
python container_scanner.py --scan

# Generate JSON report
python container_scanner.py --report --format json

# Generate CSV report
python container_scanner.py --report --format csv

# Scan with custom database
python container_scanner.py --scan --db /path/to/security.db

# Continuous monitoring mode
python container_scanner.py --monitor --interval 300
```

## 🎯 Usage Examples

### Basic Scanning

```bash
# One-time security scan
python container_scanner.py --scan

# Generate detailed report
python container_scanner.py --report --format json

# Continuous monitoring every 5 minutes
python container_scanner.py --monitor --interval 300
```

### Integration with CI/CD

```bash
# Fail build if high risk containers found
python container_scanner.py --scan --db /tmp/security.db
HIGH_RISK_COUNT=$(sqlite3 /tmp/security.db "SELECT COUNT(*) FROM container_scans WHERE risk_score > 7")
if [ $HIGH_RISK_COUNT -gt 0 ]; then
    echo "🚨 High risk containers detected - failing build"
    exit 1
fi
```

### Docker Deployment

```bash
# Build the scanner image
docker build -t container-scanner .

# Run security scan
docker run -v /var/run/docker.sock:/var/run/docker.sock container-scanner

# Run with volume for persistent storage
docker run -v /var/run/docker.sock:/var/run/docker.sock -v $(pwd)/data:/app/data container-scanner
```

## 🔧 Advanced Features

### Custom Risk Thresholds

```json
{
  "risk_thresholds": {
    "high": 8,
    "medium": 5,
    "low": 3
  }
}
```

### Alert Integration

Configure Slack/Discord webhooks for real-time alerts when high-risk containers are detected.

### Historical Analysis

The SQLite database maintains scan history for trend analysis and compliance reporting.

## 🐛 Troubleshooting

### Trivy Installation Issues

```bash
# Alternative installation method
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
```

### Docker Permission Issues

```bash
# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker
```

### Scan Timeout Solutions

```bash
# Increase timeout for large images
python container_scanner.py --scan --timeout 1200
```

## 📈 Performance Optimization

* Parallel Scanning: Multiple containers scanned concurrently
* Cached Vulnerability Data: Trivy maintains local vulnerability database
* Incremental Scanning: Only changed containers are rescanned in monitor mode
* Efficient Database: SQLite with proper indexing for fast queries

## 🤝 Contributing

```bash
# Fork the repository
# Create feature branch (git checkout -b feature/improvement)
# Commit changes (git commit -am 'Add new security check')
# Push branch (git push origin feature/improvement)
# Create Pull Request
```

### Areas for Contribution

* New security checks
* Additional vulnerability scanners
* Cloud container platform support (Kubernetes, ECS)
* Enhanced reporting formats
* Performance optimizations

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🎯 Project Purpose

Automatically scans Docker containers for security issues, identifies risks, and generates reports.

## 🔍 What It Does

### 🐳 Container Discovery

```bash
# Automatically find all running Docker containers
# Lists container IDs, names, image info, and status
```

### 🛡️ Security Checks

#### Privileged Mode Check

```python
# Checks if container is running in privileged mode
# RISK: High
```

#### Root User Check

```python
# Checks if container is running as root user
# RISK: Medium
```

#### Exposed Ports Analysis

```python
# Checks for suspicious open ports (22, 2375, 1337, 4444, etc.)
# RISK: Medium
```

#### Security Profiles Check

```python
# Checks if Seccomp/AppArmor profiles are active
# RISK: Low
```

#### Dangerous Capabilities Check

```python
# Checks for dangerous Linux capabilities (SYS_ADMIN, NET_RAW, SYS_PTRACE)
# RISK: High
```

#### Host Namespace Checks

```python
# Checks if container uses host PID/Network/IPC namespace
# RISK: High
```

#### Readonly RootFS Check

```python
# Checks if root filesystem is read-only
# RISK: Low
```

#### Vulnerability Scan

```python
# Checks container image for vulnerabilities using Trivy
# Reports CRITICAL, HIGH, MEDIUM, LOW vulnerabilities
```

### Risk Scoring System

```python
# Calculates risk score 0-10 for each container
# 0-3: Low Risk
# 4-7: Medium Risk
# 8-10: High Risk
```

### Database Logging

```sql
# All scan results stored in SQLite
```

### Reporting System

```bash
# Generates reports in JSON, CSV, or Text format
python container_scanner.py --report --format json
```

## 🎯 Real-Life Scenarios

### Scenario 1: Production Security Scan

```bash
# Scan all production containers
python container_scanner.py --scan
# OUTPUT:
# nginx-proxy: Risk Score 9/10
#   - PRIVILEGED: Yes
#   - ROOT USER: Yes
#   - CRITICAL VULNS: 3
```

### Scenario 2: CI/CD Pipeline

```bash
# Automated scan after each deployment
python container_scanner.py --scan
if [ $? -eq 1 ]; then
    echo "HIGH RISK CONTAINERS - DEPLOYMENT BLOCKED"
    exit 1
fi
```

### Scenario 3: 24/7 Monitoring

```bash
# Continuous monitoring every 5 minutes
python container_scanner.py --monitor --interval 300
# Alert example if a new high-risk container appears
# ALERT: New high-risk container: suspicious-app
```

## 🔥 Benefits for SOC Analysts

* Time Saving: From 2-3 hours manually to 2-3 minutes using the tool
* Early Detection: Identify misconfigured or vulnerable containers before production
* Compliance: Supports PCI-DSS, HIPAA, ISO27001, and container security best practices
* Incident Response: Quick scan of suspicious containers and prioritization based on risk score

## 📊 Example Output

```bash
🚀 Starting container security scan...
🔍 Scanning container: nginx (a1b2c3d4)
🔍 Scanning container: redis (e5f6g7h8)
🔍 Scanning container: postgres (i9j0k1l2)

✅ Scan completed. Scanned 3 containers.

🔴 nginx: Risk Score 9/10
🟡 redis: Risk Score 5/10
🟢 postgres: Risk Score 2/10

📊 Results: 1 high-risk container found
```
