import docker
import json
import subprocess
import requests
from datetime import datetime
import sqlite3
import os
import argparse
from pathlib import Path
import time
import sys

class ContainerSecurityScanner:
    def __init__(self, db_path="container_security.db"):
        self.client = docker.from_env()
        self.db_path = db_path
        self.init_database()

    def init_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS container_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                container_id TEXT,
                container_name TEXT,
                image TEXT,
                status TEXT,
                scan_results TEXT,
                risk_score INTEGER,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                container_id TEXT,
                event_type TEXT,
                description TEXT,
                severity TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                total_containers INTEGER,
                high_risk_count INTEGER,
                scan_duration REAL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()

    def scan_running_containers(self):
        start_time = time.time()
        containers = self.client.containers.list()
        results = {}
        high_risk_count = 0

        for container in containers:
            container_id = container.id
            container_name = container.name
            image = container.image.tags[0] if container.image.tags else container.image.id
            status = container.status

            security_checks = self.run_security_checks(container)
            risk_score = self.calculate_risk_score(security_checks)

            if risk_score > 7:
                high_risk_count += 1

            container_info = {
                'container_id': container_id,
                'container_name': container_name,
                'image': image,
                'status': status,
                'security_checks': security_checks,
                'risk_score': risk_score
            }

            results[container_name] = container_info
            self.save_scan_result(container_id, container_name, image, status, json.dumps(security_checks), risk_score)

            if risk_score > 7:
                self.log_security_event(container_id, "HIGH_RISK", f"Container has high risk score: {risk_score}", "HIGH")

        scan_duration = time.time() - start_time
        self.save_scan_history(len(containers), high_risk_count, scan_duration)

        return results

    def run_security_checks(self, container):
        checks = {
            'privileged_check': self.check_privileged(container),
            'root_user_check': self.check_root_user(container),
            'exposed_ports': self.check_exposed_ports(container),
            'seccomp_check': self.check_seccomp_profile(container),
            'apparmor_check': self.check_apparmor_profile(container),
            'capabilities_check': self.check_capabilities(container),
            'host_pid_check': self.check_host_pid(container),
            'host_network_check': self.check_host_network(container),
            'host_ipc_check': self.check_host_ipc(container),
            'readonly_rootfs': self.check_readonly_rootfs(container),
            'vulnerability_scan': self.scan_image_vulnerabilities(container)
        }
        return checks

    def check_privileged(self, container):
        privileged = container.attrs['HostConfig']['Privileged']
        return {
            'status': 'FAIL' if privileged else 'PASS',
            'details': 'Container is running in privileged mode' if privileged else 'Container is not privileged'
        }

    def check_root_user(self, container):
        user = container.attrs['Config']['User']
        is_root = user == '' or user == 'root' or user.startswith('0:')
        return {
            'status': 'FAIL' if is_root else 'PASS',
            'details': f'Container is running as root user: {user}' if is_root else 'Container is not running as root'
        }

    def check_exposed_ports(self, container):
        exposed_ports = container.attrs['Config']['ExposedPorts']
        ports = list(exposed_ports.keys()) if exposed_ports else []
        suspicious_ports = [port for port in ports if any(p in port for p in ['22', '2375', '2376', '1337', '4444'])]
        return {
            'status': 'FAIL' if suspicious_ports else 'PASS',
            'details': f'Suspicious ports exposed: {suspicious_ports}' if suspicious_ports else 'No suspicious ports exposed'
        }

    def check_seccomp_profile(self, container):
        seccomp = container.attrs['HostConfig']['SecurityOpt']
        has_seccomp = seccomp and any('seccomp' in opt for opt in seccomp)
        return {
            'status': 'PASS' if has_seccomp else 'WARN',
            'details': 'Seccomp profile is set' if has_seccomp else 'No seccomp profile set'
        }

    def check_apparmor_profile(self, container):
        apparmor = container.attrs['HostConfig']['SecurityOpt']
        has_apparmor = apparmor and any('apparmor' in opt for opt in apparmor)
        return {
            'status': 'PASS' if has_apparmor else 'WARN',
            'details': 'AppArmor profile is set' if has_apparmor else 'No AppArmor profile set'
        }

    def check_capabilities(self, container):
        caps = container.attrs['HostConfig']['CapAdd']
        dangerous_caps = ['SYS_ADMIN', 'NET_RAW', 'DAC_READ_SEARCH', 'SYS_PTRACE', 'SYS_MODULE']
        found_caps = [cap for cap in dangerous_caps if caps and cap in caps] if caps else []
        return {
            'status': 'FAIL' if found_caps else 'PASS',
            'details': f'Dangerous capabilities added: {found_caps}' if found_caps else 'No dangerous capabilities added'
        }

    def check_host_pid(self, container):
        host_pid = container.attrs['HostConfig']['PidMode'] == 'host'
        return {
            'status': 'FAIL' if host_pid else 'PASS',
            'details': 'Container using host PID namespace' if host_pid else 'Container not using host PID namespace'
        }

    def check_host_network(self, container):
        host_network = container.attrs['HostConfig']['NetworkMode'] == 'host'
        return {
            'status': 'FAIL' if host_network else 'PASS',
            'details': 'Container using host network' if host_network else 'Container not using host network'
        }

    def check_host_ipc(self, container):
        host_ipc = container.attrs['HostConfig']['IpcMode'] == 'host'
        return {
            'status': 'FAIL' if host_ipc else 'PASS',
            'details': 'Container using host IPC namespace' if host_ipc else 'Container not using host IPC namespace'
        }

    def check_readonly_rootfs(self, container):
        readonly = container.attrs['HostConfig']['ReadonlyRootfs']
        return {
            'status': 'PASS' if readonly else 'WARN',
            'details': 'Root filesystem is read-only' if readonly else 'Root filesystem is writable'
        }

    def scan_image_vulnerabilities(self, container):
        image_name = container.image.tags[0] if container.image.tags else container.image.id
        try:
            result = subprocess.run(
                ['trivy', 'image', '--format', 'json', '--timeout', '10m', image_name],
                capture_output=True, text=True, timeout=600
            )
            if result.returncode == 0:
                vuln_data = json.loads(result.stdout)
                critical_vulns = [v for v in vuln_data.get('Results', []) for v in v.get('Vulnerabilities', []) if v.get('Severity') == 'CRITICAL']
                high_vulns = [v for v in vuln_data.get('Results', []) for v in v.get('Vulnerabilities', []) if v.get('Severity') == 'HIGH']
                return {
                    'status': 'FAIL' if critical_vulns or high_vulns else 'PASS',
                    'details': f'Critical: {len(critical_vulns)}, High: {len(high_vulns)} vulnerabilities found',
                    'vulnerabilities': {
                        'critical': len(critical_vulns),
                        'high': len(high_vulns),
                        'medium': len([v for v in vuln_data.get('Results', []) for v in v.get('Vulnerabilities', []) if v.get('Severity') == 'MEDIUM']),
                        'low': len([v for v in vuln_data.get('Results', []) for v in v.get('Vulnerabilities', []) if v.get('Severity') == 'LOW'])
                    }
                }
            else:
                return {'status': 'ERROR', 'details': f'Trivy scan failed: {result.stderr}'}
        except subprocess.TimeoutExpired:
            return {'status': 'ERROR', 'details': 'Vulnerability scan timed out after 10 minutes'}
        except Exception as e:
            return {'status': 'ERROR', 'details': f'Vulnerability scan error: {str(e)}'}

    def calculate_risk_score(self, security_checks):
        score = 0
        weight_map = {
            'privileged_check': 3,
            'root_user_check': 2,
            'exposed_ports': 2,
            'seccomp_check': 1,
            'apparmor_check': 1,
            'capabilities_check': 3,
            'host_pid_check': 2,
            'host_network_check': 3,
            'host_ipc_check': 2,
            'readonly_rootfs': 1,
            'vulnerability_scan': 5
        }

        for check, result in security_checks.items():
            if result['status'] == 'FAIL':
                score += weight_map.get(check, 2)
            elif result['status'] == 'WARN':
                score += weight_map.get(check, 1) // 2
            elif result['status'] == 'ERROR':
                score += 1

        if 'vulnerability_scan' in security_checks:
            vuln_result = security_checks['vulnerability_scan']
            if 'vulnerabilities' in vuln_result:
                score += vuln_result['vulnerabilities']['critical'] * 3
                score += vuln_result['vulnerabilities']['high'] * 2
                score += vuln_result['vulnerabilities']['medium'] * 1

        return min(score, 10)

    def save_scan_result(self, container_id, container_name, image, status, scan_results, risk_score):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO container_scans (container_id, container_name, image, status, scan_results, risk_score)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (container_id, container_name, image, status, scan_results, risk_score))
        conn.commit()
        conn.close()

    def save_scan_history(self, total_containers, high_risk_count, scan_duration):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO scan_history (total_containers, high_risk_count, scan_duration)
            VALUES (?, ?, ?)
        ''', (total_containers, high_risk_count, scan_duration))
        conn.commit()
        conn.close()

    def log_security_event(self, container_id, event_type, description, severity):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO security_events (container_id, event_type, description, severity)
            VALUES (?, ?, ?, ?)
        ''', (container_id, event_type, description, severity))
        conn.commit()
        conn.close()

    def generate_report(self, output_format='json'):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT container_name, image, risk_score, timestamp FROM container_scans 
            ORDER BY timestamp DESC LIMIT 20
        ''')
        recent_scans = cursor.fetchall()

        cursor.execute('''
            SELECT COUNT(*) as total, 
                   AVG(risk_score) as avg_score,
                   MAX(risk_score) as max_score,
                   COUNT(CASE WHEN risk_score > 7 THEN 1 END) as high_risk
            FROM container_scans 
            WHERE timestamp > datetime('now', '-1 day')
        ''')
        stats = cursor.fetchone()

        conn.close()

        report_data = {
            'summary': {
                'total_scans': stats[0],
                'average_risk_score': round(stats[1] or 0, 2),
                'max_risk_score': stats[2] or 0,
                'high_risk_containers': stats[3]
            },
            'recent_scans': []
        }

        for scan in recent_scans:
            report_data['recent_scans'].append({
                'container_name': scan[0],
                'image': scan[1],
                'risk_score': scan[2],
                'timestamp': scan[3]
            })

        if output_format == 'json':
            return json.dumps(report_data, indent=2, default=str)
        elif output_format == 'csv':
            csv_output = "container_name,image,risk_score,timestamp\n"
            for item in report_data['recent_scans']:
                csv_output += f"{item['container_name']},{item['image']},{item['risk_score']},{item['timestamp']}\n"
            return csv_output
        else:
            output = f"Container Security Scan Report\n"
            output += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            output += f"Total Scans: {report_data['summary']['total_scans']}\n"
            output += f"Average Risk Score: {report_data['summary']['average_risk_score']}/10\n"
            output += f"Max Risk Score: {report_data['summary']['max_risk_score']}/10\n"
            output += f"High Risk Containers: {report_data['summary']['high_risk_containers']}\n\n"
            
            output += "Recent Scans:\n"
            for scan in report_data['recent_scans']:
                output += f"- {scan['container_name']} ({scan['image']}): Risk {scan['risk_score']}/10\n"
            
            return output

    def continuous_monitoring(self, interval=300):
        print(f"🔍 Starting continuous container monitoring (interval: {interval}s)")
        print("Press Ctrl+C to stop monitoring")
        
        try:
            while True:
                print(f"\n🕒 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Scanning containers...")
                results = self.scan_running_containers()
                
                high_risk_containers = {name: info for name, info in results.items() if info['risk_score'] > 7}
                
                if high_risk_containers:
                    print("🚨 HIGH RISK CONTAINERS DETECTED:")
                    for name, info in high_risk_containers.items():
                        print(f"   📦 {name}: Risk Score {info['risk_score']}/10")
                
                print(f"✅ Scan completed. Total: {len(results)}, High Risk: {len(high_risk_containers)}")
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\n🛑 Monitoring stopped")

def main():
    parser = argparse.ArgumentParser(description='Container Security Scanner')
    parser.add_argument('--scan', action='store_true', help='Scan running containers')
    parser.add_argument('--report', action='store_true', help='Generate report')
    parser.add_argument('--monitor', action='store_true', help='Continuous monitoring mode')
    parser.add_argument('--interval', type=int, default=300, help='Monitoring interval in seconds')
    parser.add_argument('--format', choices=['json', 'csv', 'text'], default='json', help='Report format')
    parser.add_argument('--db', default='container_security.db', help='Database path')

    args = parser.parse_args()

    if not any([args.scan, args.report, args.monitor]):
        parser.print_help()
        return

    scanner = ContainerSecurityScanner(args.db)

    if args.scan:
        print("🚀 Starting container security scan...")
        results = scanner.scan_running_containers()
        print(f"✅ Scan completed. Scanned {len(results)} containers.")
        
        high_risk = sum(1 for info in results.values() if info['risk_score'] > 7)
        print(f"📊 Results: {high_risk} high risk containers found")
        
        for name, info in results.items():
            risk_level = "🔴" if info['risk_score'] > 7 else "🟡" if info['risk_score'] > 4 else "🟢"
            print(f"{risk_level} {name}: Risk Score {info['risk_score']}/10")

    if args.report:
        report = scanner.generate_report(args.format)
        print(report)

    if args.monitor:
        scanner.continuous_monitoring(args.interval)

if __name__ == "__main__":
    main()
