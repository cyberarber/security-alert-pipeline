#!/usr/bin/env python3
"""
n8n Workflow Trigger
Sends security alerts to n8n for automated workflow processing
Author: Arber (ak@arb3r.com)
"""

import os
import json
import requests
from datetime import datetime


class N8NResponder:
    """Triggers n8n workflows for security automation"""
    
    def __init__(self):
        """Initialize n8n connection"""
        self.base_url = os.environ.get('N8N_URL', 'http://localhost:5678')
        self.webhook_url = os.environ.get('N8N_WEBHOOK_URL', '')
        
    def trigger_workflow(self, alert_data, ai_analysis):
        """
        Send alert to n8n workflow for processing
        
        Args:
            alert_data: Original alert
            ai_analysis: AI analysis results
        """
        
        # Prepare payload for n8n
        workflow_data = {
            "alert_id": alert_data.get('id', 'unknown'),
            "timestamp": alert_data.get('timestamp', datetime.now().isoformat()),
            "alert_type": alert_data.get('alert_type', 'Unknown'),
            "source_ip": alert_data.get('source_ip', 'N/A'),
            "dest_ip": alert_data.get('dest_ip', 'N/A'),
            "severity": ai_analysis.get('severity', 'medium'),
            "confidence": ai_analysis.get('confidence', 0),
            "threat_category": ai_analysis.get('threat_category', 'Unknown'),
            "recommended_action": ai_analysis.get('recommended_action', 'Review'),
            "reasoning": ai_analysis.get('reasoning', 'No context'),
            "raw_log": alert_data.get('raw_log', '')[:500]
        }
        
        # Determine which workflow to trigger based on severity
        if ai_analysis.get('severity') == 'critical':
            webhook_path = '/webhook/critical-alert'
        elif ai_analysis.get('severity') == 'high':
            webhook_path = '/webhook/high-alert'
        else:
            webhook_path = '/webhook/standard-alert'
        
        webhook_url = self.webhook_url or f"{self.base_url}{webhook_path}"
        
        try:
            response = requests.post(
                webhook_url,
                json=workflow_data,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code in [200, 201, 204]:
                print(f"✓ Triggered n8n workflow: {webhook_path}")
                return {
                    'success': True,
                    'workflow': webhook_path,
                    'response': response.text[:200] if response.text else 'Success'
                }
            else:
                print(f"✗ n8n trigger failed: {response.status_code}")
                return {'success': False, 'error': f"Status {response.status_code}"}
                
        except requests.exceptions.ConnectionError:
            print(f"✗ Cannot connect to n8n at {self.base_url}")
            return {'success': False, 'error': 'Connection failed'}
        except Exception as e:
            print(f"✗ Error triggering workflow: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def create_automation_rules(self):
        """
        Define automation rules for different alert types
        """
        rules = {
            'brute_force': {
                'actions': ['block_ip', 'reset_password', 'notify_user'],
                'severity_threshold': 'medium'
            },
            'data_exfiltration': {
                'actions': ['isolate_host', 'capture_traffic', 'create_case'],
                'severity_threshold': 'high'
            },
            'malware_detection': {
                'actions': ['quarantine', 'scan_network', 'update_signatures'],
                'severity_threshold': 'high'
            },
            'privilege_escalation': {
                'actions': ['disable_account', 'audit_logs', 'alert_admin'],
                'severity_threshold': 'critical'
            },
            'suspicious_process': {
                'actions': ['kill_process', 'memory_dump', 'investigate'],
                'severity_threshold': 'medium'
            }
        }
        return rules
    
    def test_connection(self):
        """Test n8n availability"""
        try:
            response = requests.get(
                f"{self.base_url}/healthz",
                timeout=5
            )
            if response.status_code == 200:
                print(f"✓ n8n is running at {self.base_url}")
                return True
        except:
            pass
        
        # Try alternative health check
        try:
            response = requests.get(
                self.base_url,
                timeout=5
            )
            if response.status_code in [200, 302]:
                print(f"✓ n8n is accessible at {self.base_url}")
                return True
        except Exception as e:
            print(f"✗ Cannot connect to n8n: {str(e)}")
        
        return False


def main():
    """Test n8n integration"""
    from dotenv import load_dotenv
    load_dotenv()
    
    responder = N8NResponder()
    
    print("=" * 60)
    print("N8N WORKFLOW INTEGRATION TEST")
    print("=" * 60)
    
    # Test connection
    if responder.test_connection():
        print("\n[Automation Rules Available]")
        rules = responder.create_automation_rules()
        for alert_type, config in rules.items():
            print(f"\n{alert_type.upper()}:")
            print(f"  Threshold: {config['severity_threshold']}")
            print(f"  Actions: {', '.join(config['actions'])}")
        
        # Test workflow trigger
        print("\n[Testing Workflow Trigger]")
        test_alert = {
            'id': 'test-n8n-001',
            'alert_type': 'Test Alert',
            'source_ip': '192.168.1.100',
            'dest_ip': '10.0.0.1'
        }
        test_analysis = {
            'severity': 'high',
            'confidence': 85,
            'recommended_action': 'Test workflow execution'
        }
        
        result = responder.trigger_workflow(test_alert, test_analysis)
        if result['success']:
            print(f"✓ Workflow triggered successfully")
        else:
            print(f"Note: Webhook not configured yet - this is normal")
            print(f"Configure webhook in n8n UI first")
    
    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()
