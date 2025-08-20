#!/bin/bash
# AI-Augmented DevOps Framework Demo Script
# Complete demonstration of the research implementation

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
DEMO_PORT=5000
DEMO_URL="http://localhost:${DEMO_PORT}"
WAIT_TIME=3

print_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                  🤖 AI-Augmented DevOps                     ║"
    echo "║            Intelligent Framework Demonstration               ║"
    echo "║                                                              ║"
    echo "║  Research Paper: WeDoAI 2025                                ║"
    echo "║  Authors: Akshay Mittal, Krishna Kandi                      ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${PURPLE}[STEP]${NC} $1"
}

check_prerequisites() {
    log_step "Checking prerequisites..."
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is required but not installed"
        exit 1
    fi
    
    # Check pip
    if ! command -v pip3 &> /dev/null; then
        log_error "pip3 is required but not installed"
        exit 1
    fi
    
    # Check curl
    if ! command -v curl &> /dev/null; then
        log_error "curl is required but not installed"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

setup_environment() {
    log_step "Setting up demo environment..."
    
    # Create virtual environment if it doesn't exist
    if [ ! -d "venv" ]; then
        log_info "Creating virtual environment..."
        python3 -m venv venv
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Install dependencies
    log_info "Installing dependencies..."
    pip install --quiet -r requirements.txt
    pip install --quiet -r demo_app/requirements.txt
    
    log_success "Environment setup complete"
}

start_application() {
    log_step "Starting AI-Augmented DevOps application..."
    
    # Start the Flask application in background
    cd demo_app
    export FLASK_ENV=development
    export PYTHONPATH=".."
    
    log_info "Starting web server on port ${DEMO_PORT}..."
    python app.py &
    APP_PID=$!
    cd ..
    
    # Wait for application to start
    log_info "Waiting for application to be ready..."
    for i in {1..30}; do
        if curl -s "${DEMO_URL}/api/health" > /dev/null 2>&1; then
            log_success "Application is ready!"
            break
        fi
        sleep 1
        if [ $i -eq 30 ]; then
            log_error "Application failed to start within 30 seconds"
            exit 1
        fi
    done
}

demo_health_check() {
    log_step "🏥 Health Check Demonstration"
    echo ""
    
    log_info "Checking application health..."
    response=$(curl -s "${DEMO_URL}/api/health")
    echo -e "${CYAN}Health Status:${NC}"
    echo "$response" | python3 -m json.tool
    echo ""
    sleep $WAIT_TIME
}

demo_cvss_analysis() {
    log_step "🔍 CVSS-Context Vulnerability Analysis"
    echo ""
    
    log_info "Analyzing vulnerability with contextual factors..."
    
    payload='{
        "cve_id": "CVE-2023-DEMO",
        "base_cvss_score": 7.5,
        "context": {
            "service_exposure": "public",
            "data_sensitivity": "high",
            "environment_type": "production",
            "attack_surface": 0.8,
            "user_facing": true,
            "critical_business_function": true,
            "incident_history_count": 2,
            "deployment_frequency": 3.5
        }
    }'
    
    response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "$payload" \
        "${DEMO_URL}/api/analyze-vulnerability")
    
    echo -e "${CYAN}CVSS-Context Analysis Result:${NC}"
    echo "$response" | python3 -m json.tool
    echo ""
    
    # Extract key metrics
    adjusted_score=$(echo "$response" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(f'{data[\"analysis\"][\"adjusted_score\"]:.2f}')
except:
    print('N/A')
")
    
    priority=$(echo "$response" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data['analysis']['priority'])
except:
    print('N/A')
")
    
    log_success "Vulnerability analyzed: Score adjusted to ${adjusted_score}, Priority ${priority}"
    sleep $WAIT_TIME
}

demo_anomaly_detection() {
    log_step "📊 Multi-Modal Anomaly Detection"
    echo ""
    
    log_info "Running anomaly detection on system metrics..."
    
    response=$(curl -s -X POST "${DEMO_URL}/api/detect-anomalies")
    
    echo -e "${CYAN}Anomaly Detection Result:${NC}"
    echo "$response" | python3 -m json.tool
    echo ""
    
    # Extract anomaly count
    anomaly_count=$(echo "$response" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data['anomalies_detected'])
except:
    print('0')
")
    
    log_success "Detected ${anomaly_count} anomalies with explainable AI insights"
    sleep $WAIT_TIME
}

demo_metrics_dashboard() {
    log_step "📈 Performance Metrics Dashboard"
    echo ""
    
    log_info "Fetching DORA metrics and security effectiveness..."
    
    response=$(curl -s "${DEMO_URL}/api/metrics")
    
    echo -e "${CYAN}System Metrics:${NC}"
    echo "$response" | python3 -m json.tool
    echo ""
    
    # Extract key improvements
    security_improvement=$(echo "$response" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    improvement = data['security_metrics']['critical_vulnerabilities_per_month']['improvement']
    print(improvement)
except:
    print('N/A')
")
    
    deployment_improvement=$(echo "$response" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    improvement = data['dora_metrics']['deployment_frequency']['improvement']
    print(improvement)
except:
    print('N/A')
")
    
    log_success "Security improvement: ${security_improvement}, Deployment improvement: ${deployment_improvement}"
    sleep $WAIT_TIME
}

demo_interactive_features() {
    log_step "🌐 Interactive Web Dashboard"
    echo ""
    
    log_info "The AI-Augmented DevOps framework provides an interactive web interface"
    log_info "Open your browser and navigate to: ${DEMO_URL}"
    echo ""
    log_info "Interactive features available:"
    echo "  • Real-time CVSS-Context analysis"
    echo "  • Explainable anomaly detection"
    echo "  • Security metrics visualization"
    echo "  • DORA metrics tracking"
    echo "  • AI-powered recommendations"
    echo ""
    
    read -p "Press Enter when you've explored the web interface..."
}

demo_research_results() {
    log_step "🎓 Research Results Summary"
    echo ""
    
    log_info "Key achievements from our research paper:"
    echo ""
    echo -e "${GREEN}Security Effectiveness:${NC}"
    echo "  • 87% reduction in security incidents"
    echo "  • 95.8% threat detection accuracy"
    echo "  • 4.7% false positive rate (down from 34%)"
    echo ""
    echo -e "${GREEN}Operational Performance (DORA Metrics):${NC}"
    echo "  • 340% improvement in deployment frequency"
    echo "  • 81.4% reduction in lead time"
    echo "  • 77.1% reduction in mean time to recovery"
    echo ""
    echo -e "${GREEN}Educational Impact:${NC}"
    echo "  • 67% improvement in developers' security understanding"
    echo "  • 4.2/5.0 trust score for AI explanations"
    echo "  • Embedded tutoring system effectiveness"
    echo ""
    echo -e "${GREEN}Economic Value:${NC}"
    echo "  • 458% ROI in Year 1"
    echo "  • 3.5-month breakeven point"
    echo "  • $825,000 net annual benefit"
    echo ""
}

cleanup() {
    log_step "🧹 Cleaning up demo environment"
    
    # Kill the Flask application
    if [ ! -z "${APP_PID:-}" ]; then
        log_info "Stopping application (PID: $APP_PID)..."
        kill $APP_PID 2>/dev/null || true
        wait $APP_PID 2>/dev/null || true
    fi
    
    log_success "Demo environment cleaned up"
}

main() {
    print_banner
    
    # Set up cleanup trap
    trap cleanup EXIT
    
    check_prerequisites
    setup_environment
    start_application
    
    echo ""
    log_info "🚀 Starting AI-Augmented DevOps demonstration..."
    echo ""
    
    # Run demonstration modules
    demo_health_check
    demo_cvss_analysis
    demo_anomaly_detection
    demo_metrics_dashboard
    demo_interactive_features
    demo_research_results
    
    echo ""
    log_success "🎉 Demo completed successfully!"
    echo ""
    log_info "Thank you for exploring our AI-Augmented DevOps framework!"
    log_info "For more details, see our research paper and GitHub repository."
    echo ""
    
    # Keep application running for manual exploration
    log_info "Application will continue running for manual exploration..."
    log_info "Press Ctrl+C to stop the demo"
    
    # Wait for user interrupt
    wait $APP_PID
}

# Check if script is being sourced or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
