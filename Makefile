# AI-Augmented DevOps Framework
# Makefile for development and deployment automation

.PHONY: help setup setup-dev install clean test test-cov lint format \
        demo train-models security-scan deploy-k8s evaluate generate-report \
        docker-build docker-run pre-commit-install

# Default target
.DEFAULT_GOAL := help

# Variables
PYTHON := python3
PIP := pip3
VENV := venv
APP_NAME := ai-augmented-devops
DOCKER_TAG := latest
K8S_NAMESPACE := ai-devops

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[1;33m
BLUE := \033[0;34m
NC := \033[0m # No Color

help: ## Show this help message
	@echo "$(BLUE)AI-Augmented DevOps Framework$(NC)"
	@echo "$(BLUE)================================$(NC)"
	@echo ""
	@echo "Available commands:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2}' $(MAKEFILE_LIST)

setup: ## Install dependencies and setup environment
	@echo "$(YELLOW)Setting up AI-Augmented DevOps environment...$(NC)"
	$(PYTHON) -m venv $(VENV)
	./$(VENV)/bin/pip install --upgrade pip
	./$(VENV)/bin/pip install -r requirements.txt
	@echo "$(GREEN)✓ Environment setup complete$(NC)"
	@echo "$(YELLOW)Activate with: source $(VENV)/bin/activate$(NC)"

setup-dev: setup ## Setup development environment with additional tools
	@echo "$(YELLOW)Setting up development environment...$(NC)"
	./$(VENV)/bin/pip install -r requirements-dev.txt
	./$(VENV)/bin/pre-commit install
	@echo "$(GREEN)✓ Development environment ready$(NC)"

install: ## Install package in development mode
	$(PIP) install -e .

clean: ## Clean up temporary files and caches
	@echo "$(YELLOW)Cleaning up...$(NC)"
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	find . -type f -name ".coverage" -delete
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type d -name ".mypy_cache" -exec rm -rf {} +
	rm -rf build/ dist/ .coverage htmlcov/
	@echo "$(GREEN)✓ Cleanup complete$(NC)"

test: ## Run test suite
	@echo "$(YELLOW)Running tests...$(NC)"
	$(PYTHON) -m pytest tests/ -v
	@echo "$(GREEN)✓ Tests completed$(NC)"

test-cov: ## Run tests with coverage report
	@echo "$(YELLOW)Running tests with coverage...$(NC)"
	$(PYTHON) -m pytest tests/ --cov=ai_components --cov-report=html --cov-report=term-missing
	@echo "$(GREEN)✓ Coverage report generated in htmlcov/$(NC)"

lint: ## Run linting checks
	@echo "$(YELLOW)Running linting checks...$(NC)"
	$(PYTHON) -m ruff check .
	$(PYTHON) -m mypy ai_components/
	$(PYTHON) -m bandit -r ai_components/
	@echo "$(GREEN)✓ Linting completed$(NC)"

format: ## Format code using black and ruff
	@echo "$(YELLOW)Formatting code...$(NC)"
	$(PYTHON) -m black .
	$(PYTHON) -m ruff --fix .
	@echo "$(GREEN)✓ Code formatted$(NC)"

pre-commit-install: ## Install pre-commit hooks
	@echo "$(YELLOW)Installing pre-commit hooks...$(NC)"
	pre-commit install
	@echo "$(GREEN)✓ Pre-commit hooks installed$(NC)"

demo: ## Run complete AI-Augmented DevOps demonstration
	@echo "$(BLUE)🤖 AI-Augmented DevOps Demo$(NC)"
	@echo "$(BLUE)=============================$(NC)"
	@echo "$(YELLOW)1. Running CVSS-Context Model Demo...$(NC)"
	$(PYTHON) -m ai_components.cvss_context_model
	@echo ""
	@echo "$(YELLOW)2. Running Anomaly Detection Demo...$(NC)"
	$(PYTHON) -m ai_components.anomaly_detection
	@echo ""
	@echo "$(YELLOW)3. Running Explainable AI Demo...$(NC)"
	$(PYTHON) -m ai_components.explainable_ai
	@echo ""
	@echo "$(GREEN)✓ Demo completed successfully$(NC)"

train-models: ## Train/update AI models with latest data
	@echo "$(YELLOW)Training AI models...$(NC)"
	$(PYTHON) scripts/train_models.py
	@echo "$(GREEN)✓ Model training completed$(NC)"

security-scan: ## Run comprehensive security analysis
	@echo "$(YELLOW)Running security scans...$(NC)"
	@echo "1. Running Bandit security scan..."
	$(PYTHON) -m bandit -r . -f json -o reports/bandit-report.json || true
	@echo "2. Running Safety dependency check..."
	$(PYTHON) -m safety check --json --output reports/safety-report.json || true
	@echo "3. Running Semgrep static analysis..."
	semgrep --config=auto --json --output=reports/semgrep-report.json . || true
	@echo "$(GREEN)✓ Security scan completed. Reports in reports/$(NC)"

docker-build: ## Build Docker image
	@echo "$(YELLOW)Building Docker image...$(NC)"
	docker build -t $(APP_NAME):$(DOCKER_TAG) .
	@echo "$(GREEN)✓ Docker image built: $(APP_NAME):$(DOCKER_TAG)$(NC)"

docker-run: ## Run Docker container
	@echo "$(YELLOW)Running Docker container...$(NC)"
	docker run -p 5000:5000 --name $(APP_NAME) $(APP_NAME):$(DOCKER_TAG)

deploy-k8s: ## Deploy to Kubernetes with AI policies
	@echo "$(YELLOW)Deploying to Kubernetes...$(NC)"
	kubectl create namespace $(K8S_NAMESPACE) --dry-run=client -o yaml | kubectl apply -f -
	kubectl apply -f deployment/manifests/ -n $(K8S_NAMESPACE)
	kubectl apply -f deployment/policies/ -n $(K8S_NAMESPACE)
	@echo "$(GREEN)✓ Deployed to Kubernetes namespace: $(K8S_NAMESPACE)$(NC)"

evaluate: ## Run experimental evaluation suite
	@echo "$(YELLOW)Running experimental evaluation...$(NC)"
	$(PYTHON) evaluation/security_metrics.py
	$(PYTHON) evaluation/performance_analysis.py
	$(PYTHON) evaluation/cost_benefit.py
	@echo "$(GREEN)✓ Evaluation completed. Results in evaluation/results/$(NC)"

generate-report: ## Generate explainable AI incident report
	@echo "$(YELLOW)Generating AI incident report...$(NC)"
	$(PYTHON) scripts/generate_report.py
	@echo "$(GREEN)✓ Report generated in reports/$(NC)"

benchmark: ## Run performance benchmarks
	@echo "$(YELLOW)Running performance benchmarks...$(NC)"
	$(PYTHON) scripts/benchmark.py
	@echo "$(GREEN)✓ Benchmarks completed$(NC)"

docs: ## Generate documentation
	@echo "$(YELLOW)Generating documentation...$(NC)"
	mkdocs build
	@echo "$(GREEN)✓ Documentation generated in site/$(NC)"

docs-serve: ## Serve documentation locally
	@echo "$(YELLOW)Serving documentation at http://localhost:8000$(NC)"
	mkdocs serve

init-dirs: ## Initialize required directories
	@echo "$(YELLOW)Creating required directories...$(NC)"
	mkdir -p reports/ logs/ models/ data/ evaluation/results/
	@echo "$(GREEN)✓ Directories created$(NC)"

check-deps: ## Check for dependency updates
	@echo "$(YELLOW)Checking for dependency updates...$(NC)"
	$(PIP) list --outdated
	@echo "$(GREEN)✓ Dependency check completed$(NC)"

# CI/CD Pipeline Commands
ci-install: ## Install dependencies for CI/CD
	$(PIP) install -r requirements.txt
	$(PIP) install -r requirements-dev.txt

ci-test: lint test-cov ## Run CI/CD test pipeline
	@echo "$(GREEN)✓ CI/CD pipeline completed$(NC)"

ci-security: security-scan ## Run CI/CD security pipeline
	@echo "$(GREEN)✓ Security pipeline completed$(NC)"

# Development helpers
jupyter: ## Start Jupyter notebook server
	@echo "$(YELLOW)Starting Jupyter notebook server...$(NC)"
	jupyter notebook --ip=0.0.0.0 --port=8888 --no-browser

shell: ## Open interactive Python shell with imports
	@echo "$(YELLOW)Opening Python shell...$(NC)"
	$(PYTHON) -c "from ai_components import *; import numpy as np; import pandas as pd; print('AI-Augmented DevOps shell ready!')"

install-hooks: ## Install all development hooks
	pre-commit install --hook-type pre-commit
	pre-commit install --hook-type pre-push
	pre-commit install --hook-type commit-msg

# Kubernetes helpers
k8s-status: ## Check Kubernetes deployment status
	kubectl get all -n $(K8S_NAMESPACE)

k8s-logs: ## View application logs in Kubernetes
	kubectl logs -f deployment/ai-devops-app -n $(K8S_NAMESPACE)

k8s-cleanup: ## Clean up Kubernetes resources
	kubectl delete namespace $(K8S_NAMESPACE) --ignore-not-found=true

# Model management
download-models: ## Download pre-trained models
	@echo "$(YELLOW)Downloading pre-trained models...$(NC)"
	$(PYTHON) scripts/download_models.py
	@echo "$(GREEN)✓ Models downloaded$(NC)"

validate-models: ## Validate model integrity
	@echo "$(YELLOW)Validating model integrity...$(NC)"
	$(PYTHON) scripts/validate_models.py
	@echo "$(GREEN)✓ Models validated$(NC)"

# Data management
generate-sample-data: ## Generate sample data for testing
	@echo "$(YELLOW)Generating sample data...$(NC)"
	$(PYTHON) scripts/generate_sample_data.py
	@echo "$(GREEN)✓ Sample data generated$(NC)"

# Performance monitoring
monitor: ## Start monitoring dashboard
	@echo "$(YELLOW)Starting monitoring dashboard...$(NC)"
	$(PYTHON) scripts/monitoring_dashboard.py

# Quick development workflow
dev: setup-dev pre-commit-install init-dirs ## Complete development setup
	@echo "$(GREEN)✓ Development environment ready!$(NC)"
	@echo "$(YELLOW)Next steps:$(NC)"
	@echo "  1. Activate virtual environment: source $(VENV)/bin/activate"
	@echo "  2. Run demo: make demo"
	@echo "  3. Start developing!"

# Production deployment
prod-deploy: docker-build deploy-k8s ## Build and deploy to production
	@echo "$(GREEN)✓ Production deployment completed$(NC)"

# Emergency commands
emergency-rollback: ## Emergency rollback of Kubernetes deployment
	@echo "$(RED)🚨 Emergency rollback initiated$(NC)"
	kubectl rollout undo deployment/ai-devops-app -n $(K8S_NAMESPACE)
	@echo "$(GREEN)✓ Rollback completed$(NC)"

health-check: ## Check system health
	@echo "$(YELLOW)Running health checks...$(NC)"
	$(PYTHON) scripts/health_check.py
	@echo "$(GREEN)✓ Health check completed$(NC)"
