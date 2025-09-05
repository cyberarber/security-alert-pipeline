#!/usr/bin/env python3
"""
Alert Analyzer Module
Processes security alerts using AI for intelligent triage
Author: Arber (ak@arb3r.com)
"""

import json
import os
import requests
from datetime import datetime
from typing import Dict, List, Optional
import hashlib
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class AlertAnalyzer:
    """
    Analyzes security alerts using OpenAI GPT-4 for intelligent classification
    and prioritization based on threat context and historical patterns.
    """
    
    def __init__(self, api_key: Optional[str] = None):
        """Initialize the analyzer with API configuration"""
        self.api_key = api_key or os.environ.get('OPENAI_API_KEY')
        self.base_url = "https://api.openai.com/v1/chat/completions"
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        # Severity mapping for consistent scoring
        self.severity_scores = {
            'critical': 10,
            'high': 7,
            'medium': 4,
            'low': 2,
            'informational': 1
        }
        
        # Cache for analyzed patterns
        self.pattern_cache = {}
        
    def analyze_alert(self, alert_data: Dict) -> Dict:
        """
        Analyze a single alert and return enriched information
        
        Args:
            alert_data: Dictionary containing alert information
            
        Returns:
            Dictionary with analysis results and recommendations
        """
        try:
            # Generate cache key for similar alerts
            cache_key = self._generate_cache_key(alert_data)
            
            # Check if we've seen similar pattern
            if cache_key in self.pattern_cache:
                logger.info("Using cached analysis for similar alert pattern")
                cached_result = self.pattern_cache[cache_key].copy()
                cached_result['cached'] = True
                return cached_result
            
            # Prepare context for AI analysis
            analysis_prompt = self._build_analysis_prompt(alert_data)
            
            # Call OpenAI API
            response = self._call_openai(analysis_prompt)
            
            # Parse and structure the response
            result = self._parse_ai_response(response, alert_data)
            
            # Cache the result
            self.pattern_cache[cache_key] = result.copy()
            
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing alert: {str(e)}")
            return self._fallback_analysis(alert_data)
    
    def _build_analysis_prompt(self, alert_data: Dict) -> str:
        """Build the prompt for AI analysis"""
        prompt = f"""Analyze this security alert and provide assessment:

Alert Details:
- Type: {alert_data.get('alert_type', 'Unknown')}
- Source: {alert_data.get('source_ip', 'N/A')}
- Destination: {alert_data.get('dest_ip', 'N/A')}
- Description: {alert_data.get('description', 'No description')}
- Raw Log: {alert_data.get('raw_log', 'N/A')[:500]}

Provide analysis in this exact JSON format:
{{
    "severity": "critical|high|medium|low",
    "threat_category": "specific category",
    "confidence": 0-100,
    "indicators": ["list", "of", "IOCs"],
    "recommended_action": "specific action to take",
    "reasoning": "brief explanation"
}}"""
        
        return prompt
    
    def _call_openai(self, prompt: str) -> Dict:
        """Make API call to OpenAI"""
        payload = {
            "model": "gpt-4",
            "messages": [
                {
                    "role": "system",
                    "content": "You are a senior security analyst specializing in threat detection and incident response."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.3,
            "max_tokens": 500
        }
        
        response = requests.post(
            self.base_url,
            headers=self.headers,
            json=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"OpenAI API error: {response.status_code}")
    
    def _parse_ai_response(self, response: Dict, original_alert: Dict) -> Dict:
        """Parse and validate AI response"""
        try:
            content = response['choices'][0]['message']['content']
            
            # Extract JSON from response
            import re
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            if json_match:
                analysis = json.loads(json_match.group())
            else:
                analysis = json.loads(content)
            
            # Add metadata
            analysis['timestamp'] = datetime.now().isoformat()
            analysis['alert_id'] = original_alert.get('id', 'unknown')
            analysis['score'] = self.severity_scores.get(
                analysis.get('severity', 'medium'), 
                4
            )
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error parsing AI response: {str(e)}")
            return self._fallback_analysis(original_alert)
    
    def _fallback_analysis(self, alert_data: Dict) -> Dict:
        """Fallback analysis when AI is unavailable"""
        return {
            'severity': 'medium',
            'threat_category': 'Requires Manual Review',
            'confidence': 50,
            'indicators': [],
            'recommended_action': 'Manual review required',
            'reasoning': 'AI analysis unavailable, defaulting to manual review',
            'timestamp': datetime.now().isoformat(),
            'alert_id': alert_data.get('id', 'unknown'),
            'score': 4,
            'fallback': True
        }
    
    def _generate_cache_key(self, alert_data: Dict) -> str:
        """Generate cache key for alert pattern"""
        key_parts = [
            alert_data.get('alert_type', ''),
            alert_data.get('source_ip', ''),
            alert_data.get('dest_ip', ''),
            alert_data.get('description', '')[:100]
        ]
        
        key_string = '|'.join(key_parts)
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def batch_analyze(self, alerts: List[Dict]) -> List[Dict]:
        """Analyze multiple alerts efficiently"""
        results = []
        
        for alert in alerts:
            logger.info(f"Analyzing alert {alert.get('id', 'unknown')}")
            result = self.analyze_alert(alert)
            results.append(result)
        
        return results
    
    def get_statistics(self) -> Dict:
        """Get analysis statistics"""
        return {
            'patterns_cached': len(self.pattern_cache),
            'cache_size_kb': len(str(self.pattern_cache)) / 1024
        }
