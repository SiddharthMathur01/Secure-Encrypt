import os
import re
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import argparse

LOGS_DIR = 'CyberSecurity\Secure-Encrypt\logs'
APP_LOG = os.path.join(LOGS_DIR, 'app.log')
SECURITY_LOG = os.path.join(LOGS_DIR, 'security.log')
ERROR_LOG = os.path.join(LOGS_DIR, 'error.log')


class LogAnalyzer:
    
    def __init__(self):
        self.app_logs = []
        self.security_logs = []
        self.error_logs = []
        
    def load_logs(self):
        if os.path.exists(APP_LOG):
            with open(APP_LOG, 'r', encoding='utf-8') as f:
                self.app_logs = f.readlines()
        
        if os.path.exists(SECURITY_LOG):
            with open(SECURITY_LOG, 'r', encoding='utf-8') as f:
                self.security_logs = f.readlines()
        
        if os.path.exists(ERROR_LOG):
            with open(ERROR_LOG, 'r', encoding='utf-8') as f:
                self.error_logs = f.readlines()
    
    def parse_log_line(self, line):

        pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - (.*?) - (.*?) - (.*)'
        match = re.match(pattern, line)
        
        if match:
            return {
                'timestamp': match.group(1),
                'name': match.group(2),
                'level': match.group(3),
                'message': match.group(4)
            }
        return None
    
    def analyze_api_requests(self):

        print("\n" + "="*70)
        print("API REQUEST STATISTICS")
        print("="*70)
        
        endpoints = Counter()
        status_codes = Counter()
        ip_addresses = Counter()
        
        for line in self.app_logs:
            if 'API Request' in line:
                parsed = self.parse_log_line(line)
                if parsed:
                    msg = parsed['message']
                    
                    endpoint_match = re.search(r'Endpoint: ([^,]+)', msg)
                    if endpoint_match:
                        endpoints[endpoint_match.group(1).strip()] += 1
                    

                    status_match = re.search(r'Status: (\d+)', msg)
                    if status_match:
                        status_codes[status_match.group(1)] += 1
                    
                    ip_match = re.search(r'IP: ([^\s]+)', msg)
                    if ip_match:
                        ip = ip_match.group(1).strip()
                        if ip != 'Unknown':
                            ip_addresses[ip] += 1
        
        print("\n Top Endpoints:")
        for endpoint, count in endpoints.most_common(10):
            print(f"  {endpoint}: {count} requests")
        
        print("\n Status Codes:")
        for code, count in sorted(status_codes.items()):
            print(f"  {code}: {count} responses")
        
        print("\n Top IP Addresses:")
        for ip, count in ip_addresses.most_common(10):
            print(f"  {ip}: {count} requests")
    
    def analyze_encryption_operations(self):
        print("\n" + "="*70)
        print(" ENCRYPTION/DECRYPTION STATISTICS")
        print("="*70)
        
        encryption_types = Counter()
        decryption_types = Counter()
        encryption_success = 0
        encryption_failed = 0
        decryption_success = 0
        decryption_failed = 0
        
        for line in self.security_logs:
            if 'Encryption successful' in line:
                encryption_success += 1
                type_match = re.search(r'Type: ([^,]+)', line)
                if type_match:
                    encryption_types[type_match.group(1).strip()] += 1
            
            elif 'Encryption failed' in line:
                encryption_failed += 1
            
            elif 'Decryption successful' in line:
                decryption_success += 1
                type_match = re.search(r'Type: ([^,]+)', line)
                if type_match:
                    decryption_types[type_match.group(1).strip()] += 1
            
            elif 'Decryption failed' in line:
                decryption_failed += 1
        
        print(f"\n Encryption Operations:")
        print(f"  Successful: {encryption_success}")
        print(f"  Failed: {encryption_failed}")
        print(f"  Success Rate: {encryption_success/(encryption_success+encryption_failed)*100:.1f}%" 
              if (encryption_success + encryption_failed) > 0 else "  Success Rate: N/A")
        
        print(f"\n Decryption Operations:")
        print(f"  Successful: {decryption_success}")
        print(f"  Failed: {decryption_failed}")
        print(f"  Success Rate: {decryption_success/(decryption_success+decryption_failed)*100:.1f}%" 
              if (decryption_success + decryption_failed) > 0 else "  Success Rate: N/A")
        
        print("\n Encryption by Type:")
        for op_type, count in encryption_types.most_common():
            print(f"  {op_type}: {count}")
        
        print("\n Decryption by Type:")
        for op_type, count in decryption_types.most_common():
            print(f"  {op_type}: {count}")
    
    def analyze_security_events(self):
        print("\n" + "="*70)
        print("SECURITY EVENTS")
        print("="*70)
        
        security_events = Counter()
        weak_passphrase_attempts = 0
        expired_file_access = 0
        decryption_failures = 0
        
        for line in self.security_logs:
            if 'Security Event' in line:
                type_match = re.search(r'Type: ([^,]+)', line)
                if type_match:
                    event_type = type_match.group(1).strip()
                    security_events[event_type] += 1
                    
                    if event_type == 'WEAK_PASSPHRASE':
                        weak_passphrase_attempts += 1
                    elif event_type == 'EXPIRED_FILE_ACCESS':
                        expired_file_access += 1
            
            elif 'DECRYPTION_FAILED' in line:
                decryption_failures += 1
        
        print(f"\nSecurity Event Summary:")
        print(f"  Weak Passphrase Attempts: {weak_passphrase_attempts}")
        print(f"  Expired File Access Attempts: {expired_file_access}")
        print(f"  Decryption Failures: {decryption_failures}")
        
        if security_events:
            print("\nAll Security Events:")
            for event, count in security_events.most_common():
                print(f"  {event}: {count}")
    
    def analyze_errors(self):
        print("\n" + "="*70)
        print("ERROR ANALYSIS")
        print("="*70)
        
        error_types = Counter()
        
        for line in self.error_logs:
            if 'Error Type:' in line:
                type_match = re.search(r'Error Type: ([^,]+)', line)
                if type_match:
                    error_types[type_match.group(1).strip()] += 1
        
        total_errors = sum(error_types.values())
        print(f"\nTotal Errors: {total_errors}")
        
        if error_types:
            print("\nError Types:")
            for error_type, count in error_types.most_common():
                percentage = (count / total_errors * 100) if total_errors > 0 else 0
                print(f"  {error_type}: {count} ({percentage:.1f}%)")
        else:
            print("No errors found!")
    
    def analyze_time_distribution(self):
        print("\n" + "="*70)
        print("TIME DISTRIBUTION")
        print("="*70)
        
        hourly_activity = defaultdict(int)
        
        for line in self.app_logs + self.security_logs:
            parsed = self.parse_log_line(line)
            if parsed:
                try:
                    dt = datetime.strptime(parsed['timestamp'], '%Y-%m-%d %H:%M:%S')
                    hourly_activity[dt.hour] += 1
                except:
                    pass
        
        if hourly_activity:
            print("\nActivity by Hour (24h format):")
            max_count = max(hourly_activity.values())
            for hour in sorted(hourly_activity.keys()):
                count = hourly_activity[hour]
                bar = '█' * int((count / max_count) * 50)
                print(f"  {hour:02d}:00 | {bar} {count}")
    
    def generate_summary(self):
        print("\n" + "="*70)
        print("SUMMARY")
        print("="*70)
        
        print(f"\nLog Files:")
        print(f"  App Log Lines: {len(self.app_logs)}")
        print(f"  Security Log Lines: {len(self.security_logs)}")
        print(f"  Error Log Lines: {len(self.error_logs)}")
        print(f"  Total Log Lines: {len(self.app_logs) + len(self.security_logs) + len(self.error_logs)}")
        
        if self.app_logs:
            first_log = self.parse_log_line(self.app_logs[0])
            last_log = self.parse_log_line(self.app_logs[-1])
            
            if first_log and last_log:
                print(f"\nTime Range:")
                print(f"  First Log: {first_log['timestamp']}")
                print(f"  Last Log: {last_log['timestamp']}")
    
    def run_analysis(self):
        """Run all analyses"""
        print("\n" + "="*70)
        print("SECURE-ENCRYPT LOG ANALYSIS")
        print("="*70)
        
        self.load_logs()
        
        if not any([self.app_logs, self.security_logs, self.error_logs]):
            print("\n No log files found! Make sure the application has been run.")
            return
        
        self.generate_summary()
        self.analyze_api_requests()
        self.analyze_encryption_operations()
        self.analyze_security_events()
        self.analyze_errors()
        self.analyze_time_distribution()
        
        print("\n" + "="*70)
        print(" Analysis Complete")
        print("="*70 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description='Analyze Secure-Encrypt application logs'
    )
    parser.add_argument(
        '--logs-dir',
        default='logs',
        help='Path to logs directory (default: logs)'
    )
    
    args = parser.parse_args()
    
    global LOGS_DIR, APP_LOG, SECURITY_LOG, ERROR_LOG
    LOGS_DIR = args.logs_dir
    APP_LOG = os.path.join(LOGS_DIR, 'app.log')
    SECURITY_LOG = os.path.join(LOGS_DIR, 'security.log')
    ERROR_LOG = os.path.join(LOGS_DIR, 'error.log')
    
    analyzer = LogAnalyzer()
    analyzer.run_analysis()


if __name__ == '__main__':
    main()
