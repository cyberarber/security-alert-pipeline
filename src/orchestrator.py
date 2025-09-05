#!/usr/bin/env python3
"""
Security Orchestration Platform
Complete pipeline with all integrations
Author: Arber (ak@arb3r.com)
"""

import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from analyzers.alert_analyzer import AlertAnalyzer
from collectors.wazuh_collector import WazuhCollector
from responders.thehive_responder import TheHiveResponder
from responders.n8n_responder import N8NResponder
from dotenv import load_dotenv


class SecurityOrchestrator:
    """Orchestrates the complete security automation pipeline"""
    
    def __init__(self):
        """Initialize all components"""
        load_dotenv()
        self.analyzer = AlertAnalyzer()
        self.wazuh = WazuhCollector()
        self.thehive = TheHiveResponder()
        self.n8n = N8NResponder()
        
    def process_alert(self, alert_data):
        """
        Complete processing pipeline for a security alert
        """
        print(f"\n{'='*60}")
        print(f"Processing Alert: {alert_data.get('id', 'Unknown')}")
        print(f"Type: {alert_data.get('alert_type', 'Unknown')}")
        
        # Step 1: AI Analysis
        print("→ Running AI analysis...")
        analysis = self.analyzer.analyze_alert(alert_data)
        print(f"  Severity: {analysis['severity'].upper()}")
        print(f"  Confidence: {analysis.get('confidence', 'N/A')}%")
        
        # Step 2: n8n Workflow Trigger (all severities)
        print("→ Triggering n8n workflow...")
        n8n_result = self.n8n.trigger_workflow(alert_data, analysis)
        if n8n_result['success']:
            print(f"  ✓ Workflow triggered: {n8n_result['workflow']}")
        
        # Step 3: TheHive Case Creation (high/critical only)
        if analysis['severity'] in ['high', 'critical']:
            print("→ Creating TheHive case...")
            case_result = self.thehive.create_case_from_alert(alert_data, analysis)
            if case_result['success']:
                print(f"  ✓ Case #{case_result['case_number']} created")
        
        # Step 4: Return complete results
        return {
            'alert': alert_data,
            'analysis': analysis,
            'n8n': n8n_result,
            'thehive': case_result if analysis['severity'] in ['high', 'critical'] else None
        }
    
    def run_demo(self):
        """Run demonstration of full orchestration"""
        print("=" * 60)
        print("SECURITY ORCHESTRATION PLATFORM")
        print("AI + Wazuh + TheHive + n8n Integration")
        print("=" * 60)
        
        # Demo alerts
        demo_alerts = [
            {
                'id': 'orch-001',
                'timestamp': datetime.now().isoformat(),
                'alert_type': 'Ransomware Activity',
                'source_ip': '192.168.1.50',
                'dest_ip': '45.142.122.85',
                'description': 'Ransomware encryption behavior detected',
                'raw_log': 'vssadmin.exe delete shadows /all /quiet'
            },
            {
                'id': 'orch-002',
                'timestamp': datetime.now().isoformat(),
                'alert_type': 'Successful Authentication',
                'source_ip': '10.0.0.100',
                'dest_ip': '192.168.1.10',
                'description': 'User login successful',
                'raw_log': 'Successful login for user admin'
            }
        ]
        
        stats = {
            'total': 0,
            'cases_created': 0,
            'workflows_triggered': 0
        }
        
        for alert in demo_alerts:
            result = self.process_alert(alert)
            stats['total'] += 1
            if result.get('n8n', {}).get('success'):
                stats['workflows_triggered'] += 1
            if result.get('thehive', {}).get('success'):
                stats['cases_created'] += 1
        
        print("\n" + "=" * 60)
        print("ORCHESTRATION COMPLETE")
        print(f"Alerts Processed: {stats['total']}")
        print(f"TheHive Cases Created: {stats['cases_created']}")
        print(f"n8n Workflows Triggered: {stats['workflows_triggered']}")
        print("=" * 60)


def main():
    orchestrator = SecurityOrchestrator()
    orchestrator.run_demo()


if __name__ == "__main__":
    main()
