import re
from datetime import datetime

class LogParser:
    def __init__(self):
        # Regex for standard IPv4 addresses
        self.ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        
        # Mapping patterns to categories
        self.signatures = {
            'PFSENSE': r'filterlog|block|reject|pfsense',
            'AUTH': r'Failed password|invalid user|authentication failure|sshd',
            'TRAFFIC': r'proto TCP|proto UDP|length|accept'
        }

    def parse_auto(self, raw_line):
        """
        Main entry point: Analyzes a string and returns a structured dictionary.
        """
        # 1. Default Fallback Values
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        event_type = "GENERAL_LOG"
        severity = "LOW"
        
        # 2. Extract IP Addresses (Source is usually first, Destination second)
        ips = re.findall(self.ip_pattern, raw_line)
        src_ip = ips[0] if len(ips) > 0 else "0.0.0.0"
        dst_ip = ips[1] if len(ips) > 1 else "0.0.0.0"

        # 3. Determine Format & Assign Severity
        # Priority 1: Auth Logs (High Security Risk)
        if re.search(self.signatures['AUTH'], raw_line, re.IGNORECASE):
            event_type = "AUTH_FAILURE"
            severity = "HIGH"
        
        # Priority 2: pfSense/Firewall Logs (Operational Security)
        elif re.search(self.signatures['PFSENSE'], raw_line, re.IGNORECASE):
            event_type = "FIREWALL_BLOCK"
            severity = "MEDIUM"
        
        # Priority 3: General Network Traffic
        elif re.search(self.signatures['TRAFFIC'], raw_line, re.IGNORECASE):
            event_type = "NET_TRAFFIC"
            severity = "LOW"

        # 4. Return Structured Data for DB and SocketIO
        return {
            "timestamp": timestamp,
            "ip": src_ip,              # Display IP for Dashboard
            "source_ip": src_ip,       # Stored in DB
            "destination_ip": dst_ip,  # Stored in DB
            "type": event_type,
            "severity": severity,
            "msg": raw_line.strip()[:150] # Cleaned and truncated for UI
        }

# --- Standalone Testing Block ---
if __name__ == "__main__":
    parser = LogParser()
    sample_logs = [
        "May 4 12:00:01 sshd[123]: Failed password for root from 192.168.1.10 port 22",
        "pfsense: filterlog: block 10.0.0.5 -> 172.16.0.1 proto TCP",
        "Standard traffic: 192.168.1.5 -> 8.8.8.8 length 64"
    ]

    print(f"{'SEVERITY':<10} | {'TYPE':<15} | {'SOURCE IP'}")
    print("-" * 50)
    for log in sample_logs:
        res = parser.parse_auto(log)
        print(f"{res['severity']:<10} | {res['type']:<15} | {res['ip']}")