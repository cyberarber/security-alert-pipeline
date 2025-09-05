#!/usr/bin/env python3
"""
TheHive Case Creator
Automatically creates cases for high-priority security alerts
Author: Arber (ak@arb3r.com)
"""

import os
import json
import requests
from datetime import datetime


class TheHiveResponder:
    """Creates and manages cases in TheHive"""
    
    def __init__(self):
        """Initialize TheHive connection"""
        self.url = os.environ.get('THEHIVE_URL', 'http://localhost:9000')
        self.api_key = os.environ.get('THEHIVE_API_KEY', 'default_api_key')
        self.headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }
        
    def create_case_from_alert(self, alert_data, ai_analysis):
        """
        Create a TheHive case from analyzed alert using REST API
        
        Args:
            alert_data: Original alert dictionary
            ai_analysis: AI analysis results
        """
        
        # Determine case severity
        severity = self._get_severity_level(ai_analysis.get('severity', 'medium'))
        
        # Build case
        case_data = {
            "title": f"[{ai_analysis.get('severity', 'MEDIUM').upper()}] {alert_data.get('alert_type', 'Security Alert')}",
            "description": f"""
## Alert Details
- Alert ID: {alert_data.get('id', 'Unknown')}
- Timestamp: {alert_data.get('timestamp', datetime.now().isoformat())}
- Source IP: {alert_data.get('source_ip', 'N/A')}
- Destination IP: {alert_data.get('dest_ip', 'N/A')}

## AI Analysis
- Severity: {ai_analysis.get('severity', 'Unknown').upper()}
- Confidence: {ai_analysis.get('confidence', 'N/A')}%
- Threat Category: {ai_analysis.get('threat_category', 'Unknown')}

## Recommended Actions
{ai_analysis.get('recommended_action', 'Manual review required')}

## Reasoning
{ai_analysis.get('reasoning', 'No additional context available')}

## Raw Log
{alert_data.get('raw_log', 'No log data available')[:1000]}
""",
            "severity": severity,
            "tlp": 2,
            "pap": 2,
            "tags": [
                "ai-analyzed",
                f"severity:{ai_analysis.get('severity', 'unknown')}",
                alert_data.get('alert_type', 'unknown').replace(' ', '_').lower()
            ],
            "flag": True if severity >= 3 else False,
            "startDate": int(datetime.now().timestamp() * 1000)
        }
        
        try:
            # Create case via REST API
            response = requests.post(
                f"{self.url}/api/case",
                headers=self.headers,
                json=case_data,
                verify=False
            )
            
            if response.status_code in [200, 201]:
                case_json = response.json()
                case_id = case_json.get('_id', 'unknown')
                case_number = case_json.get('caseId', case_json.get('number', 'unknown'))
                
                print(f"✓ Created TheHive case #{case_number} (ID: {case_id})")
                
                return {
                    'success': True,
                    'case_id': case_id,
                    'case_number': case_number,
                    'url': f"{self.url}/cases/{case_id}/details"
                }
            else:
                print(f"✗ Failed to create case: {response.status_code} - {response.text[:200]}")
                return {'success': False, 'error': response.text}
                
        except Exception as e:
            print(f"✗ Error creating case: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _get_severity_level(self, severity):
        """Map severity to TheHive severity level (1-4)"""
        mapping = {
            'critical': 4,
            'high': 3,
            'medium': 2,
            'low': 1
        }
        return mapping.get(severity.lower(), 2)
    
    def test_connection(self):
        """Test TheHive API connection"""
        try:
            response = requests.get(
                f"{self.url}/api/case",
                headers=self.headers,
                params={"range": "0-1"},
                verify=False
            )
            
            if response.status_code == 200:
                print(f"✓ Connected to TheHive successfully")
                return True
            elif response.status_code == 401:
                print(f"✗ Authentication failed - check API key")
                return False
            else:
                print(f"✗ TheHive connection failed: {response.status_code}")
                return False
        except requests.exceptions.ConnectionError:
            print(f"✗ Cannot connect to TheHive at {self.url}")
            print("  Is TheHive running? Check: docker ps | grep thehive")
            return False
        except Exception as e:
            print(f"✗ Unexpected error: {str(e)}")
            return False


def main():
    """Test TheHive integration"""
    from dotenv import load_dotenv
    load_dotenv()
    
    responder = TheHiveResponder()
    
    print("=" * 60)
    print("THEHIVE INTEGRATION TEST")
    print("=" * 60)
    
    # Test connection
    print("\nTesting connection to TheHive...")
    if responder.test_connection():
        # Create test case
        test_alert = {
            'id': 'test-001',
            'timestamp': datetime.now().isoformat(),
            'alert_type': 'Test Security Alert',
            'source_ip': '10.0.0.1',
            'dest_ip': '192.168.1.1',
            'description': 'Test case creation',
            'raw_log': 'This is a test log entry for TheHive integration'
        }
        
        test_analysis = {
            'severity': 'high',
            'confidence': 95,
            'threat_category': 'Test Category',
            'recommended_action': 'This is a test - no action required',
            'reasoning': 'Testing TheHive integration with AI pipeline'
        }
        
        print("\nCreating test case...")
        result = responder.create_case_from_alert(test_alert, test_analysis)
        
        if result['success']:
            print(f"✓ Success! View case at: {result['url']}")
        else:
            print(f"✗ Failed: {result['error']}")
    else:
        print("\nTroubleshooting steps:")
        print("1. Check TheHive is running: docker ps | grep thehive")
        print("2. Access TheHive UI: http://localhost:9000")
        print("3. Create API key in TheHive")
        print("4. Add to .env file: THEHIVE_API_KEY=your_key_here")
    
    print("=" * 60)


if __name__ == "__main__":
    main()
