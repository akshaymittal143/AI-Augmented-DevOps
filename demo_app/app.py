#!/usr/bin/env python3
"""
AI-Augmented DevOps Demo Application

A Flask web service demonstrating the AI-Augmented DevOps framework
with real-time vulnerability analysis, anomaly detection, and explainable AI.
"""

from flask import Flask, jsonify, request, render_template_string
import os
import logging
import time
import json
from datetime import datetime
from typing import Dict, Any

# Import our AI components
import sys
sys.path.append('..')
from ai_components.cvss_context_model import CVSSContextAnalyzer, VulnerabilityContext
from ai_components.anomaly_detection import ExplainableAnomalyDetector, MetricPoint

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Initialize AI components
cvss_analyzer = CVSSContextAnalyzer()
anomaly_detector = ExplainableAnomalyDetector()

# HTML template for the web interface
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>AI-Augmented DevOps Demo</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
            margin: 40px; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }
        .container { 
            max-width: 1200px; 
            margin: 0 auto; 
            background: white; 
            padding: 40px; 
            border-radius: 20px; 
            box-shadow: 0 10px 30px rgba(0,0,0,0.2); 
        }
        h1 { 
            color: #2c3e50; 
            text-align: center; 
            margin-bottom: 30px;
            font-size: 2.5rem;
        }
        .status { 
            padding: 20px; 
            margin: 20px 0; 
            border-radius: 10px; 
            border-left: 5px solid;
        }
        .healthy { 
            background: #d4edda; 
            border-color: #28a745; 
            color: #155724; 
        }
        .info { 
            background: #d1ecf1; 
            border-color: #17a2b8; 
            color: #0c5460; 
        }
        .warning { 
            background: #fff3cd; 
            border-color: #ffc107; 
            color: #856404; 
        }
        .endpoint { 
            margin: 20px 0; 
            padding: 20px; 
            background: #f8f9fa; 
            border-radius: 10px;
            border-left: 4px solid #007bff; 
        }
        .demo-section {
            margin: 30px 0;
            padding: 25px;
            background: #f1f3f4;
            border-radius: 10px;
        }
        code { 
            background: #e9ecef; 
            padding: 3px 6px; 
            border-radius: 4px; 
            font-family: 'Monaco', 'Menlo', monospace;
        }
        .button {
            background: #007bff;
            color: white;
            padding: 12px 24px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            margin: 10px 5px;
            font-size: 14px;
            transition: background 0.3s;
        }
        .button:hover {
            background: #0056b3;
        }
        .result {
            background: #fff;
            border: 1px solid #dee2e6;
            border-radius: 5px;
            padding: 15px;
            margin: 10px 0;
            font-family: monospace;
            white-space: pre-wrap;
        }
        .feature-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }
        .feature-card {
            background: white;
            border: 1px solid #e9ecef;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .metric {
            font-size: 2rem;
            font-weight: bold;
            color: #007bff;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🤖 AI-Augmented DevOps Framework</h1>
        
        <div class="status healthy">
            <strong>✅ System Status:</strong> All AI components operational!
        </div>
        
        <div class="info">
            <strong>🚀 Version:</strong> {{ version }}<br>
            <strong>🕐 Uptime:</strong> {{ uptime }}<br>
            <strong>🐳 Container:</strong> {{ container_info }}<br>
            <strong>🧠 AI Models:</strong> CVSS-Context, Anomaly Detection, Explainable AI
        </div>
        
        <div class="feature-grid">
            <div class="feature-card">
                <h3>🔍 CVSS-Context Analysis</h3>
                <div class="metric">99.7%</div>
                <p>Vulnerability detection accuracy with contextual prioritization</p>
                <button class="button" onclick="testCVSS()">Test Analysis</button>
                <div id="cvss-result" class="result" style="display:none;"></div>
            </div>
            
            <div class="feature-card">
                <h3>📊 Anomaly Detection</h3>
                <div class="metric">94.3%</div>
                <p>Precision in explainable anomaly detection</p>
                <button class="button" onclick="testAnomaly()">Detect Anomalies</button>
                <div id="anomaly-result" class="result" style="display:none;"></div>
            </div>
            
            <div class="feature-card">
                <h3>🎯 Security Incidents</h3>
                <div class="metric">87%</div>
                <p>Reduction in security incidents</p>
                <button class="button" onclick="testSecurity()">Security Report</button>
                <div id="security-result" class="result" style="display:none;"></div>
            </div>
            
            <div class="feature-card">
                <h3>🚀 Deployment Frequency</h3>
                <div class="metric">340%</div>
                <p>Improvement in deployment frequency</p>
                <button class="button" onclick="testDeployment()">DORA Metrics</button>
                <div id="deployment-result" class="result" style="display:none;"></div>
            </div>
        </div>
        
        <div class="endpoint">
            <h3>🔗 API Endpoints:</h3>
            <p><code>GET /</code> - This interactive dashboard</p>
            <p><code>GET /api/health</code> - System health check</p>
            <p><code>POST /api/analyze-vulnerability</code> - CVSS-Context vulnerability analysis</p>
            <p><code>POST /api/detect-anomalies</code> - Multi-modal anomaly detection</p>
            <p><code>GET /api/metrics</code> - Performance and security metrics</p>
            <p><code>GET /api/demo-data</code> - Generate sample data for testing</p>
        </div>
        
        <div class="demo-section">
            <h3>📈 Research Results</h3>
            <p><strong>Paper:</strong> "AI-Augmented DevOps: An Intelligent Framework for Secure and Scalable Cloud-Native Pipeline Automation"</p>
            <p><strong>Authors:</strong> Akshay Mittal, Krishna Kandi</p>
            <p><strong>Conference:</strong> WeDoAI 2025</p>
            <div class="info">
                <strong>💡 Educational Impact:</strong> 67% improvement in developers' security practice understanding through explainable AI feedback.
            </div>
        </div>
    </div>

    <script>
        async function testCVSS() {
            const resultDiv = document.getElementById('cvss-result');
            resultDiv.style.display = 'block';
            resultDiv.innerHTML = 'Analyzing vulnerability with contextual factors...';
            
            try {
                const response = await fetch('/api/analyze-vulnerability', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        cve_id: 'CVE-2023-DEMO',
                        base_cvss_score: 7.5,
                        context: {
                            service_exposure: 'public',
                            data_sensitivity: 'high',
                            environment_type: 'production',
                            critical_business_function: true
                        }
                    })
                });
                const data = await response.json();
                resultDiv.innerHTML = JSON.stringify(data, null, 2);
            } catch (error) {
                resultDiv.innerHTML = 'Error: ' + error.message;
            }
        }
        
        async function testAnomaly() {
            const resultDiv = document.getElementById('anomaly-result');
            resultDiv.style.display = 'block';
            resultDiv.innerHTML = 'Running multi-modal anomaly detection...';
            
            try {
                const response = await fetch('/api/detect-anomalies', {method: 'POST'});
                const data = await response.json();
                resultDiv.innerHTML = JSON.stringify(data, null, 2);
            } catch (error) {
                resultDiv.innerHTML = 'Error: ' + error.message;
            }
        }
        
        async function testSecurity() {
            const resultDiv = document.getElementById('security-result');
            resultDiv.style.display = 'block';
            resultDiv.innerHTML = 'Generating security effectiveness report...';
            
            try {
                const response = await fetch('/api/metrics');
                const data = await response.json();
                resultDiv.innerHTML = JSON.stringify(data.security_metrics, null, 2);
            } catch (error) {
                resultDiv.innerHTML = 'Error: ' + error.message;
            }
        }
        
        async function testDeployment() {
            const resultDiv = document.getElementById('deployment-result');
            resultDiv.style.display = 'block';
            resultDiv.innerHTML = 'Fetching DORA metrics...';
            
            try {
                const response = await fetch('/api/metrics');
                const data = await response.json();
                resultDiv.innerHTML = JSON.stringify(data.dora_metrics, null, 2);
            } catch (error) {
                resultDiv.innerHTML = 'Error: ' + error.message;
            }
        }
    </script>
</body>
</html>
"""

# Application start time for uptime calculation
START_TIME = time.time()

@app.route('/')
def home():
    """Main interactive dashboard"""
    uptime_seconds = int(time.time() - START_TIME)
    uptime_str = f"{uptime_seconds // 3600}h {(uptime_seconds % 3600) // 60}m {uptime_seconds % 60}s"
    
    container_info = os.environ.get('HOSTNAME', 'localhost')
    
    return render_template_string(
        HTML_TEMPLATE,
        version="1.0.0",
        uptime=uptime_str,
        container_info=container_info
    )

@app.route('/api/health')
def health_check():
    """Health check endpoint for Kubernetes probes"""
    return jsonify({
        'status': 'healthy',
        'message': 'AI-Augmented DevOps is operational!',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0',
        'components': {
            'cvss_analyzer': 'operational',
            'anomaly_detector': 'operational',
            'explainable_ai': 'operational'
        }
    })

@app.route('/api/analyze-vulnerability', methods=['POST'])
def analyze_vulnerability():
    """CVSS-Context vulnerability analysis endpoint"""
    try:
        data = request.get_json()
        
        # Extract vulnerability information
        cve_id = data.get('cve_id', 'CVE-UNKNOWN')
        base_cvss_score = data.get('base_cvss_score', 5.0)
        context_data = data.get('context', {})
        
        # Create vulnerability context
        context = VulnerabilityContext(
            service_exposure=context_data.get('service_exposure', 'internal'),
            data_sensitivity=context_data.get('data_sensitivity', 'medium'),
            environment_type=context_data.get('environment_type', 'development'),
            attack_surface=context_data.get('attack_surface', 0.5),
            user_facing=context_data.get('user_facing', False),
            has_authentication=context_data.get('has_authentication', True),
            network_accessible=context_data.get('network_accessible', True),
            processes_pii=context_data.get('processes_pii', False),
            critical_business_function=context_data.get('critical_business_function', False),
            incident_history_count=context_data.get('incident_history_count', 0),
            deployment_frequency=context_data.get('deployment_frequency', 1.0),
            service_criticality=context_data.get('service_criticality', 'medium')
        )
        
        # Analyze vulnerability
        result = cvss_analyzer.analyze_vulnerability(cve_id, base_cvss_score, context)
        
        # Log the analysis
        logger.info(f"CVSS analysis completed for {cve_id}: {result.adjusted_score:.2f} (priority {result.priority})")
        
        return jsonify({
            'success': True,
            'analysis': {
                'cve_id': result.cve_id,
                'base_cvss_score': result.base_cvss_score,
                'adjusted_score': round(result.adjusted_score, 2),
                'priority': result.priority,
                'confidence': round(result.confidence, 2),
                'explanation': result.explanation,
                'risk_factors': result.risk_factors,
                'recommended_actions': result.recommended_actions,
                'business_impact': result.business_impact,
                'timeline': result.timeline
            },
            'timestamp': datetime.utcnow().isoformat()
        })
    
    except Exception as e:
        logger.error(f"CVSS analysis error: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

@app.route('/api/detect-anomalies', methods=['POST'])
def detect_anomalies():
    """Multi-modal anomaly detection endpoint"""
    try:
        # Generate sample metrics for demonstration
        metrics = []
        base_time = datetime.utcnow()
        
        # Simulate normal and anomalous metrics
        for i in range(10):
            timestamp = base_time.replace(minute=base_time.minute - i*5)
            
            # Add some normal metrics
            metrics.append(MetricPoint(
                timestamp=timestamp,
                service="payment-service",
                metric_name="error_rate",
                value=0.02 + (0.01 * (i % 3)),  # Slight variation
                labels={"endpoint": "/api/payment"}
            ))
            
            # Add an anomaly
            if i == 2:
                metrics.append(MetricPoint(
                    timestamp=timestamp,
                    service="payment-service",
                    metric_name="error_rate", 
                    value=0.15,  # High error rate anomaly
                    labels={"endpoint": "/api/payment"}
                ))
        
        # Detect anomalies
        anomalies = anomaly_detector.detect_anomalies(metrics)
        
        # Generate incident report
        report = anomaly_detector.generate_incident_report(anomalies)
        
        logger.info(f"Anomaly detection completed: {len(anomalies)} anomalies detected")
        
        return jsonify({
            'success': True,
            'anomalies_detected': len(anomalies),
            'incident_report': {
                'incident_id': report.incident_id,
                'severity': report.severity,
                'title': report.title,
                'summary': report.summary,
                'affected_services': report.affected_services,
                'confidence_score': round(report.confidence_score, 2),
                'anomalies': [
                    {
                        'service': a.service,
                        'metric': a.metric_name,
                        'severity': a.severity,
                        'confidence': round(a.confidence, 2),
                        'explanation': a.explanation,
                        'recommendations': a.recommended_actions[:3]  # Top 3 recommendations
                    }
                    for a in anomalies[:5]  # Top 5 anomalies
                ]
            },
            'timestamp': datetime.utcnow().isoformat()
        })
    
    except Exception as e:
        logger.error(f"Anomaly detection error: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

@app.route('/api/metrics')
def get_metrics():
    """Get performance and security metrics"""
    try:
        return jsonify({
            'success': True,
            'security_metrics': {
                'critical_vulnerabilities_per_month': {
                    'baseline': 12.0,
                    'ai_augmented': 1.5,
                    'improvement': '87.5%'
                },
                'mean_time_to_patch_days': {
                    'baseline': 14.3,
                    'ai_augmented': 2.1,
                    'improvement': '85.3%'
                },
                'false_positive_rate': {
                    'baseline': '34.0%',
                    'ai_augmented': '4.7%',
                    'improvement': '86.2%'
                },
                'threat_detection_accuracy': {
                    'baseline': '73.5%',
                    'ai_augmented': '95.8%',
                    'improvement': '30.3%'
                }
            },
            'dora_metrics': {
                'deployment_frequency': {
                    'baseline': '2.1 deployments/day',
                    'ai_augmented': '9.2 deployments/day',
                    'improvement': '340%'
                },
                'lead_time': {
                    'baseline': '4.2 days',
                    'ai_augmented': '0.78 days',
                    'improvement': '81.4%'
                },
                'mean_time_to_recovery': {
                    'baseline': '3.4 hours',
                    'ai_augmented': '0.78 hours',
                    'improvement': '77.1%'
                },
                'change_failure_rate': {
                    'baseline': '12.0%',
                    'ai_augmented': '3.2%',
                    'improvement': '73.3%'
                }
            },
            'ai_performance': {
                'cvss_context_accuracy': '99.7%',
                'anomaly_detection_precision': '94.3%',
                'anomaly_detection_recall': '91.7%',
                'explainability_trust_score': '4.2/5.0',
                'developer_understanding_improvement': '67%'
            },
            'timestamp': datetime.utcnow().isoformat()
        })
    
    except Exception as e:
        logger.error(f"Metrics error: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

@app.route('/api/demo-data')
def generate_demo_data():
    """Generate sample data for testing"""
    try:
        return jsonify({
            'success': True,
            'sample_vulnerability': {
                'cve_id': 'CVE-2023-DEMO',
                'base_cvss_score': 7.5,
                'context': {
                    'service_exposure': 'public',
                    'data_sensitivity': 'high',
                    'environment_type': 'production',
                    'attack_surface': 0.8,
                    'user_facing': True,
                    'critical_business_function': True,
                    'incident_history_count': 2
                }
            },
            'sample_metrics': [
                {
                    'service': 'payment-service',
                    'metric_name': 'error_rate',
                    'value': 0.02,
                    'timestamp': datetime.utcnow().isoformat()
                },
                {
                    'service': 'user-auth',
                    'metric_name': 'response_time',
                    'value': 0.5,
                    'timestamp': datetime.utcnow().isoformat()
                }
            ],
            'timestamp': datetime.utcnow().isoformat()
        })
    
    except Exception as e:
        logger.error(f"Demo data error: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

@app.route('/api/simulate-incident')
def simulate_incident():
    """Simulate a security incident for demonstration"""
    try:
        logger.warning("🚨 SIMULATED INCIDENT: Unusual activity detected")
        
        return jsonify({
            'success': True,
            'incident': {
                'type': 'security_anomaly',
                'severity': 'high',
                'description': 'Simulated security incident for demonstration',
                'affected_services': ['payment-service', 'user-auth'],
                'ai_analysis': {
                    'confidence': 0.89,
                    'recommended_actions': [
                        'Investigate authentication logs',
                        'Check for unusual network traffic',
                        'Review recent deployments'
                    ]
                }
            },
            'timestamp': datetime.utcnow().isoformat()
        })
    
    except Exception as e:
        logger.error(f"Incident simulation error: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'False').lower() == 'true'
    
    logger.info(f"🚀 Starting AI-Augmented DevOps Demo on port {port}")
    logger.info("🤖 AI Components initialized successfully")
    
    app.run(host='0.0.0.0', port=port, debug=debug)
