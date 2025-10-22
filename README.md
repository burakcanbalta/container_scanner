# 🐳 Container Security Scanner

A comprehensive container security assessment tool designed for DevOps and security teams. Automatically scan running Docker containers for security misconfigurations, vulnerabilities, and compliance issues with real-time risk scoring and reporting.

---

🚀 Quick Start

Prerequisites

```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install Trivy for vulnerability scanning
wget https://github.com/aquasecurity/trivy/releases/download/v0.45.1/trivy_0.45.1_Linux-64bit.tar.gz
tar -xzf trivy_0.45.1_Linux-64bit.tar.gz
sudo mv trivy /usr/local/bin/
```

Installation & Setup

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

Basic Usage

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

🎯 Usage Examples

Basic Scanning

```bash
# One-time security scan
python container_scanner.py --scan

# Generate detailed report
python container_scanner.py --report --format json

# Continuous monitoring every 5 minutes
python container_scanner.py --monitor --interval 300
```

Integration with CI/CD

```bash
# Fail build if high risk containers found
python container_scanner.py --scan --db /tmp/security.db
HIGH_RISK_COUNT=$(sqlite3 /tmp/security.db "SELECT COUNT(*) FROM container_scans WHERE risk_score > 7")
if [ $HIGH_RISK_COUNT -gt 0 ]; then
    echo "🚨 High risk containers detected - failing build"
    exit 1
fi
```

Docker Deployment

```bash
# Build the scanner image
docker build -t container-scanner .

# Run security scan
docker run -v /var/run/docker.sock:/var/run/docker.sock container-scanner

# Run with volume for persistent storage
docker run -v /var/run/docker.sock:/var/run/docker.sock -v $(pwd)/data:/app/data container-scanner
```

🔧 Advanced Features

Custom Risk Thresholds

```json
{
  "risk_thresholds": {
    "high": 8,
    "medium": 5,
    "low": 3
  }
}
```

Alert Integration
Configure Slack/Discord webhooks for real-time alerts when high-risk containers are detected.

Historical Analysis
The SQLite database maintains scan history for trend analysis and compliance reporting.

🐛 Troubleshooting

Trivy Installation Issues

```bash
# Alternative installation method
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
```

Docker Permission Issues

```bash
# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker
```

Scan Timeout Solutions

```bash
# Increase timeout for large images
python container_scanner.py --scan --timeout 1200
```

📈 Performance Optimization

* Parallel Scanning: Multiple containers scanned concurrently
* Cached Vulnerability Data: Trivy maintains local vulnerability database
* Incremental Scanning: Only changed containers are rescanned in monitor mode
* Efficient Database: SQLite with proper indexing for fast queries

🤝 Contributing

```bash
# Fork the repository
# Create feature branch (git checkout -b feature/improvement)
# Commit changes (git commit -am 'Add new security check')
# Push branch (git push origin feature/improvement)
# Create Pull Request
```

Areas for Contribution:

* New security checks
* Additional vulnerability scanners
* Cloud container platform support (Kubernetes, ECS)
* Enhanced reporting formats
* Performance optimizations

📄 License
This project is licensed under the MIT License - see the LICENSE file for details.
