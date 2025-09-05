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
    
    def get_manager_logs(self, limit=100):
        """
        Fetch recent manager logs from Wazuh
        This works with Wazuh 4.7 API
        """
        if not self.token or datetime.now() >= self.token_expire:
            if not self.authenticate():
                return []
        
        logs_url = f"{self.base_url}/manager/logs"
        
        headers = {
            'Authorization': f'Bearer {self.token}',
            'Content-Type': 'application/json'
        }
        
        params = {
            'pretty': 'true',
            'limit': limit,
            'sort': '-timestamp'
        }
        
        try:
            response = requests.get(
                logs_url,
                headers=headers,
                params=params,
                verify=False
            )
            
            if response.status_code == 200:
                data = response.json()
                logs = data.get('data', {}).get('affected_items', [])
                print(f"✓ Retrieved {len(logs)} log entries from Wazuh")
                return logs
            else:
                print(f"✗ Failed to get logs: {response.status_code}")
                return []
                
        except Exception as e:
            print(f"✗ Error fetching logs: {str(e)}")
            return []
    
    def get_agents_status(self):
        """Get status of all registered agents"""
        if not self.token or datetime.now() >= self.token_expire:
            if not self.authenticate():
                return []
        
        agents_url = f"{self.base_url}/agents"
        
        headers = {
            'Authorization': f'Bearer {self.token}',
            'Content-Type': 'application/json'
        }
        
        try:
            response = requests.get(
                agents_url,
                headers=headers,
                verify=False
            )
            
            if response.status_code == 200:
                data = response.json()
                agents = data.get('data', {}).get('affected_items', [])
                print(f"✓ Found {len(agents)} registered agents")
                return agents
            else:
                print(f"✗ Failed to get agents: {response.status_code}")
                return []
                
        except Exception as e:
            print(f"✗ Error fetching agents: {str(e)}")
            return []


def main():
    """Test the Wazuh collector"""
    from dotenv import load_dotenv
    load_dotenv()
    
    collector = WazuhCollector()
    
    print("=" * 60)
    print("WAZUH COLLECTOR TEST")
    print("=" * 60)
    
    # Test authentication
    if collector.authenticate():
        print("\n[1] Testing Manager Logs Retrieval:")
        logs = collector.get_manager_logs(limit=5)
        if logs:
            print(f"   Sample log entry: {logs[0].get('description', 'N/A')[:80]}...")
        
        print("\n[2] Testing Agent Status:")
        agents = collector.get_agents_status()
        for agent in agents[:3]:  # Show first 3 agents
            print(f"   Agent: {agent.get('name', 'unknown')} - Status: {agent.get('status', 'unknown')}")
    
    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()
