#!/usr/bin/env python3
"""
Integrated Security Pipeline
Combines AI analysis with automated case creation
Author: Arber (ak@arb3r.com)
"""

import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from analyzers.alert_analyzer import AlertAnalyzer
from responders.thehive_responder import TheHiveResponder
from dotenv import load_dotenv


def process_security_alert(alert_data):
    """
    Complete pipeline: Analyze → Decide → Respond
    """
    print(f"\n[{alert_data['id']}] Processing alert: {alert_data['alert_type']}")
    
    # Step 1: AI Analysis
    analyzer = AlertAnalyzer()
    analysis = analyzer.analyze_alert(alert_data)
    
    print(f"  AI Severity: {analysis['severity'].upper()}")
    print(f"  Confidence: {analysis.get('confidence', 'N/A')}%")
    
    # Step 2: Decision Logic
    if analysis['severity'] in ['critical', 'high']:
        print(f"  → Creating TheHive case (severity: {analysis['severity']})")
        
        # Step 3: Automated Response
        responder = TheHiveResponder()
        result = responder.create_case_from_alert(alert_data, analysis)
        
        if result['success']:
            print(f"  ✓ Case created: {result['case_number']}")
            return {'alert': alert_data, 'analysis': analysis, 'case': result}
    else:
        print(f"  → Low priority, logged only (severity: {analysis['severity']})")
        return {'alert': alert_data, 'analysis': analysis, 'case': None}


def main():
    """Demonstrate integrated pipeline"""
    load_dotenv()
    
    print("=" * 60)
    print("INTEGRATED SECURITY PIPELINE DEMO")
    print("AI Analysis → Automated Case Creation")
    print("=" * 60)
    
    # Test alerts
    test_alerts = [
        {
            'id': 'alert-001',
            'timestamp': datetime.now().isoformat(),
            'alert_type': 'Ransomware Detection',
            'source_ip': '192.168.1.100',
            'dest_ip': '45.142.122.85',
            'description': 'WannaCry ransomware indicators detected',
            'raw_log': 'Process cmd.exe spawned wmic.exe shadowcopy delete'
        },
        {
            'id': 'alert-002',
            'timestamp': datetime.now().isoformat(),
            'alert_type': 'Port Scan',
            'source_ip': '10.0.0.50',
            'dest_ip': '192.168.1.0/24',
            'description': 'Network reconnaissance activity',
            'raw_log': 'SYN packets to ports 21,22,23,25,80,443,3389'
        }
    ]
    
    cases_created = 0
    
    for alert in test_alerts:
        result = process_security_alert(alert)
        if result['case']:
            cases_created += 1
    
    print("\n" + "=" * 60)
    print(f"Pipeline Complete: {cases_created} cases auto-created in TheHive")
    print("=" * 60)


if __name__ == "__main__":
    main()
