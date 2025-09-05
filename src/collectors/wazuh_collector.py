#!/usr/bin/env python3
"""
Wazuh Alert Collector
Pulls real-time alerts from Wazuh API
Author: Arber (ak@arb3r.com)
"""

import os
import json
import requests
from datetime import datetime, timedelta
import urllib3

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WazuhCollector:
    """Collects alerts from Wazuh SIEM"""
    
    def __init__(self):
        """Initialize with credentials from environment"""
        self.base_url = os.environ.get('WAZUH_API_URL', 'https://localhost:55000')
        self.username = os.environ.get('WAZUH_USERNAME', 'wazuh')
        self.password = os.environ.get('WAZUH_PASSWORD', 'wazuh')
        self.token = None
        self.token_expire = None
        
    def authenticate(self):
        """Get authentication token from Wazuh"""
        auth_url = f"{self.base_url}/security/user/authenticate"
        
        try:
            response = requests.post(
                auth_url,
                auth=(self.username, self.password),
                verify=False
            )
            
            if response.status_code == 200:
                data = response.json()
                self.token = data['data']['token']
                self.token_expire = datetime.now() + timedelta(minutes=15)
                print("✓ Authenticated with Wazuh API")
                return True
            else:
                print(f"✗ Authentication failed: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"✗ Connection error: {str(e)}")
            return False
    
    def get_recent_alerts(self, minutes=60, min_level=5):
        """
        Fetch recent alerts from Wazuh
        
        Args:
            minutes: How far back to look (default 60)
            min_level: Minimum alert level (default 5)
        """
        # Ensure we have valid token
        if not self.token or datetime.now() >= self.token_expire:
            if not self.authenticate():
                return []
        
        # Calculate time range
        end_time = datetime.now()
        start_time = end_time - timedelta(minutes=minutes)
        
        # API endpoint for alerts
        alerts_url = f"{self.base_url}/alerts"
        
        headers = {
            'Authorization': f'Bearer {self.token}',
            'Content-Type': 'application/json'
        }
        
        params = {
            'pretty': 'true',
            'level': f'>{min_level}',
            'limit': 100,
            'sort': '-timestamp'
        }
        
        try:
            response = requests.get(
                alerts_url,
                headers=headers,
                params=params,
                verify=False
            )
            
            if response.status_code == 200:
                data = response.json()
                alerts = data.get('data', {}).get('affected_items', [])
                print(f"✓ Retrieved {len(alerts)} alerts from Wazuh")
                return alerts
            else:
                print(f"✗ Failed to get alerts: {response.status_code}")
                return []
                
        except Exception as e:
            print(f"✗ Error fetching alerts: {str(e)}")
            return []
    
    def format_alert(self, wazuh_alert):
        """Convert Wazuh alert format to our standard format"""
        return {
            'id': wazuh_alert.get('id', 'unknown'),
            'timestamp': wazuh_alert.get('timestamp', datetime.now().isoformat()),
            'alert_type': wazuh_alert.get('rule', {}).get('description', 'Unknown'),
            'source_ip': wazuh_alert.get('data', {}).get('srcip', 'N/A'),
            'dest_ip': wazuh_alert.get('data', {}).get('dstip', 'N/A'),
            'description': wazuh_alert.get('rule', {}).get('description', ''),
            'level': wazuh_alert.get('rule', {}).get('level', 0),
            'agent': wazuh_alert.get('agent', {}).get('name', 'unknown'),
            'raw_log': wazuh_alert.get('full_log', '')[:500]
        }


def main():
    """Test the Wazuh collector"""
    from dotenv import load_dotenv
    load_dotenv()
    
    collector = WazuhCollector()
    
    # Test authentication
    if collector.authenticate():
        # Get recent alerts
        alerts = collector.get_recent_alerts(minutes=60, min_level=3)
        
        # Format and display
        for alert in alerts[:5]:  # Show first 5
            formatted = collector.format_alert(alert)
            print(f"\nAlert: {formatted['id']}")
            print(f"  Type: {formatted['alert_type']}")
            print(f"  Level: {formatted['level']}")
            print(f"  Agent: {formatted['agent']}")


if __name__ == "__main__":
    main()
