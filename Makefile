# LinkShield Backend - Comprehensive Makefile
# Security Testing, Validation, Deployment Preparation, and Monitoring Setup
# 
# This Makefile provides convenient automation for all security-related 
# development and deployment tasks following the three-phase security implementation.

.PHONY: help install test security performance deploy monitor clean lint format
.DEFAULT_GOAL := help

# =============================================================================
# CONFIGURATION
# =============================================================================

# Python and environment settings
PYTHON := python3
PIP := pip3
VENV := env
VENV_ACTIVATE := source $(VENV)/bin/activate

# Project directories
SRC_DIR := src
TEST_DIR := tests
DOCS_DIR := docs
SCRIPTS_DIR := scripts
MONITORING_DIR := monitoring

# Docker settings
DOCKER_COMPOSE := docker-compose
DOCKER_COMPOSE_TEST := docker-compose -f docker-compose.test.yml
DOCKER_IMAGE := linkshield-backend
DOCKER_TAG := latest

# Testing settings
PYTEST_ARGS := -v --tb=short --strict-markers --disable-warnings --color=yes
PYTEST_COV_ARGS := --cov=$(SRC_DIR) --cov-report=html --cov-report=term-missing
PYTEST_SECURITY_ARGS := -m "not slow" --maxfail=5

# Security validation settings
SECURITY_SCRIPT := $(SCRIPTS_DIR)/security_validation.py
DEPLOYMENT_CHECKLIST := $(SCRIPTS_DIR)/deployment_security_checklist.py

# =============================================================================
# HELP AND INFORMATION
# =============================================================================

help: ## Show this help message
	@echo "LinkShield Backend - Security-Enhanced Development Automation"
	@echo "============================================================="
	@echo ""
	@echo "Available targets:"
	@echo ""
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "Security Testing Workflows:"
	@echo "  make test-all          - Run all tests (unit, integration, security, performance)"
	@echo "  make security-full     - Complete security validation and testing"
	@echo "  make deploy-check      - Full deployment readiness validation"
	@echo "  make monitor-setup     - Initialize monitoring and alerting"

# =============================================================================
# ENVIRONMENT SETUP
# =============================================================================

install: ## Install all dependencies and setup development environment
	@echo "Setting up LinkShield Backend development environment..."
	$(PIP) install -r requirements.txt
	$(PIP) install -r requirements-test.txt
	@echo "Environment setup complete!"

install-dev: install ## Install development dependencies with additional tools
	$(PIP) install black flake8 mypy bandit safety pre-commit
	pre-commit install
	@echo "Development environment setup complete!"

venv: ## Create and activate virtual environment
	$(PYTHON) -m venv $(VENV)
	$(VENV_ACTIVATE) && $(PIP) install --upgrade pip
	$(VENV_ACTIVATE) && $(PIP) install -r requirements.txt
	@echo "Virtual environment created. Activate with: source $(VENV)/bin/activate"

clean: ## Clean up temporary files and caches
	@echo "Cleaning up temporary files..."
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf .pytest_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	rm -rf dist/
	rm -rf build/
	@echo "Cleanup complete!"

# =============================================================================
# CODE QUALITY AND LINTING
# =============================================================================

lint: ## Run code linting and static analysis
	@echo "Running code quality checks..."
	flake8 $(SRC_DIR) $(TEST_DIR) --max-line-length=100 --exclude=migrations
	mypy $(SRC_DIR) --ignore-missing-imports
	@echo "Linting complete!"

format: ## Format code using black
	@echo "Formatting code..."
	black $(SRC_DIR) $(TEST_DIR) --line-length=100
	@echo "Code formatting complete!"

security-lint: ## Run security-focused static analysis
	@echo "Running security static analysis..."
	bandit -r $(SRC_DIR) -f json -o security-report.json
	bandit -r $(SRC_DIR) -f txt
	safety check --json --output safety-report.json
	safety check
	@echo "Security static analysis complete!"

# =============================================================================
# TESTING - UNIT AND BASIC TESTS
# =============================================================================

test: ## Run basic unit tests
	@echo "Running unit tests..."
	pytest $(TEST_DIR) $(PYTEST_ARGS) -m "unit or not integration"
	@echo "Unit tests complete!"

test-unit: ## Run unit tests with coverage
	@echo "Running unit tests with coverage..."
	pytest $(TEST_DIR) $(PYTEST_ARGS) $(PYTEST_COV_ARGS) -m "unit"
	@echo "Unit tests with coverage complete!"

test-integration: ## Run integration tests
	@echo "Running integration tests..."
	pytest $(TEST_DIR)/integration $(PYTEST_ARGS) -m "integration"
	@echo "Integration tests complete!"

# =============================================================================
# SECURITY TESTING
# =============================================================================

test-security: ## Run all security tests
	@echo "Running comprehensive security tests..."
	pytest $(TEST_DIR)/security $(PYTEST_ARGS) $(PYTEST_SECURITY_ARGS)
	@echo "Security tests complete!"

test-security-auth: ## Run authentication security tests
	@echo "Running authentication security tests..."
	pytest $(TEST_DIR)/security/test_authentication_fixes.py $(PYTEST_ARGS)
	pytest $(TEST_DIR)/security/test_session_management.py $(PYTEST_ARGS)
	@echo "Authentication security tests complete!"

test-security-rate-limiting: ## Run rate limiting security tests
	@echo "Running rate limiting security tests..."
	pytest $(TEST_DIR)/security/test_distributed_rate_limiting.py $(PYTEST_ARGS)
	@echo "Rate limiting security tests complete!"

test-security-ssrf: ## Run SSRF protection tests
	@echo "Running SSRF protection tests..."
	pytest $(TEST_DIR)/security/test_ssrf_protection.py $(PYTEST_ARGS)
	@echo "SSRF protection tests complete!"

test-security-api-keys: ## Run API key security tests
	@echo "Running API key security tests..."
	pytest $(TEST_DIR)/security/test_api_key_security.py $(PYTEST_ARGS)
	@echo "API key security tests complete!"

test-security-validation: ## Run input validation security tests
	@echo "Running input validation security tests..."
	pytest $(TEST_DIR)/security/test_input_validation.py $(PYTEST_ARGS)
	@echo "Input validation security tests complete!"

test-security-access-control: ## Run access control security tests
	@echo "Running access control security tests..."
	pytest $(TEST_DIR)/security/test_access_control.py $(PYTEST_ARGS)
	@echo "Access control security tests complete!"

test-security-logging: ## Run secure logging tests
	@echo "Running secure logging tests..."
	pytest $(TEST_DIR)/security/test_secure_logging.py $(PYTEST_ARGS)
	pytest $(TEST_DIR)/security/test_security_notifications.py $(PYTEST_ARGS)
	@echo "Secure logging tests complete!"

test-security-timing: ## Run timing attack protection tests
	@echo "Running timing attack protection tests..."
	pytest $(TEST_DIR)/security/test_constant_time_operations.py $(PYTEST_ARGS)
	@echo "Timing attack protection tests complete!"

# =============================================================================
# PERFORMANCE TESTING
# =============================================================================

test-performance: ## Run all performance tests
	@echo "Running performance tests..."
	pytest $(TEST_DIR)/performance $(PYTEST_ARGS) -m "performance"
	@echo "Performance tests complete!"

test-performance-rate-limiting: ## Run rate limiting performance tests
	@echo "Running rate limiting performance tests..."
	pytest $(TEST_DIR)/performance/test_rate_limiting_performance.py $(PYTEST_ARGS)
	@echo "Rate limiting performance tests complete!"

test-performance-validation: ## Run validation performance tests
	@echo "Running validation performance tests..."
	pytest $(TEST_DIR)/performance/test_validation_performance.py $(PYTEST_ARGS)
	@echo "Validation performance tests complete!"

test-performance-middleware: ## Run middleware performance tests
	@echo "Running middleware performance tests..."
	pytest $(TEST_DIR)/performance/test_security_middleware_performance.py $(PYTEST_ARGS)
	@echo "Middleware performance tests complete!"

# =============================================================================
# COMPREHENSIVE TEST SUITES
# =============================================================================

test-all: ## Run all tests (unit, integration, security, performance)
	@echo "Running comprehensive test suite..."
	@echo "=================================="
	@echo "1. Unit Tests"
	@make test-unit
	@echo ""
	@echo "2. Integration Tests"
	@make test-integration
	@echo ""
	@echo "3. Security Tests"
	@make test-security
	@echo ""
	@echo "4. Performance Tests"
	@make test-performance
	@echo ""
	@echo "All tests complete!"

test-ci: ## Run tests suitable for CI/CD pipeline
	@echo "Running CI/CD test suite..."
	pytest $(TEST_DIR) $(PYTEST_ARGS) $(PYTEST_COV_ARGS) -m "not slow and not manual"
	@echo "CI/CD tests complete!"

test-security-full: ## Run comprehensive security test suite
	@echo "Running full security test suite..."
	@echo "=================================="
	@make test-security-auth
	@make test-security-rate-limiting
	@make test-security-ssrf
	@make test-security-api-keys
	@make test-security-validation
	@make test-security-access-control
	@make test-security-logging
	@make test-security-timing
	@echo "Full security test suite complete!"

# =============================================================================
# SECURITY VALIDATION AND SCRIPTS
# =============================================================================

security-validate: ## Run automated security validation script
	@echo "Running security validation..."
	$(PYTHON) $(SECURITY_SCRIPT) --comprehensive --report
	@echo "Security validation complete!"

security-validate-quick: ## Run quick security validation
	@echo "Running quick security validation..."
	$(PYTHON) $(SECURITY_SCRIPT) --quick
	@echo "Quick security validation complete!"

security-validate-report: ## Generate detailed security validation report
	@echo "Generating security validation report..."
	$(PYTHON) $(SECURITY_SCRIPT) --report --output security-validation-report.json
	@echo "Security validation report generated!"

security-full: ## Complete security validation and testing
	@echo "Running complete security validation..."
	@echo "====================================="
	@make security-lint
	@make test-security-full
	@make security-validate
	@echo "Complete security validation finished!"

# =============================================================================
# DEPLOYMENT PREPARATION
# =============================================================================

deploy-check: ## Run deployment readiness validation
	@echo "Running deployment readiness checks..."
	$(PYTHON) $(DEPLOYMENT_CHECKLIST) --comprehensive
	@echo "Deployment readiness validation complete!"

deploy-check-quick: ## Run quick deployment checks
	@echo "Running quick deployment checks..."
	$(PYTHON) $(DEPLOYMENT_CHECKLIST) --quick
	@echo "Quick deployment checks complete!"

deploy-check-security: ## Run security-focused deployment checks
	@echo "Running security deployment checks..."
	$(PYTHON) $(DEPLOYMENT_CHECKLIST) --security-focus
	@echo "Security deployment checks complete!"

deploy-validate-config: ## Validate deployment configuration
	@echo "Validating deployment configuration..."
	@echo "Checking environment variables..."
	$(PYTHON) -c "from src.config.settings import Settings; Settings()"
	@echo "Checking Docker configuration..."
	$(DOCKER_COMPOSE) config
	@echo "Configuration validation complete!"

deploy-prepare: ## Prepare for production deployment
	@echo "Preparing for production deployment..."
	@echo "===================================="
	@make clean
	@make security-full
	@make deploy-check
	@make deploy-validate-config
	@echo "Production deployment preparation complete!"

# =============================================================================
# MONITORING AND ALERTING
# =============================================================================

monitor-setup: ## Initialize monitoring and alerting systems
	@echo "Setting up monitoring systems..."
	$(PYTHON) $(MONITORING_DIR)/security_monitoring.py --setup
	$(PYTHON) $(MONITORING_DIR)/performance_monitoring.py --setup
	@echo "Monitoring setup complete!"

monitor-test: ## Test monitoring systems
	@echo "Testing monitoring systems..."
	$(PYTHON) $(MONITORING_DIR)/security_monitoring.py --test
	$(PYTHON) $(MONITORING_DIR)/performance_monitoring.py --test
	@echo "Monitoring tests complete!"

monitor-start: ## Start monitoring services
	@echo "Starting monitoring services..."
	$(PYTHON) $(MONITORING_DIR)/security_monitoring.py --start
	$(PYTHON) $(MONITORING_DIR)/performance_monitoring.py --start
	@echo "Monitoring services started!"

monitor-status: ## Check monitoring system status
	@echo "Checking monitoring system status..."
	$(PYTHON) $(MONITORING_DIR)/security_monitoring.py --status
	$(PYTHON) $(MONITORING_DIR)/performance_monitoring.py --status
	@echo "Monitoring status check complete!"

# =============================================================================
# DOCKER OPERATIONS
# =============================================================================

docker-build: ## Build Docker image
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .
	@echo "Docker image built successfully!"

docker-build-test: ## Build Docker image for testing
	@echo "Building test Docker image..."
	docker build -t $(DOCKER_IMAGE):test -f Dockerfile.test .
	@echo "Test Docker image built successfully!"

docker-up: ## Start services with Docker Compose
	@echo "Starting services with Docker Compose..."
	$(DOCKER_COMPOSE) up -d
	@echo "Services started!"

docker-up-test: ## Start test environment with Docker Compose
	@echo "Starting test environment..."
	$(DOCKER_COMPOSE_TEST) up -d
	@echo "Test environment started!"

docker-down: ## Stop Docker Compose services
	@echo "Stopping Docker Compose services..."
	$(DOCKER_COMPOSE) down
	@echo "Services stopped!"

docker-down-test: ## Stop test Docker Compose services
	@echo "Stopping test environment..."
	$(DOCKER_COMPOSE_TEST) down
	@echo "Test environment stopped!"

docker-logs: ## View Docker Compose logs
	$(DOCKER_COMPOSE) logs -f

docker-test: ## Run tests in Docker environment
	@echo "Running tests in Docker environment..."
	$(DOCKER_COMPOSE_TEST) run --rm api pytest $(PYTEST_ARGS)
	@echo "Docker tests complete!"

docker-security-test: ## Run security tests in Docker environment
	@echo "Running security tests in Docker environment..."
	$(DOCKER_COMPOSE_TEST) run --rm api pytest $(TEST_DIR)/security $(PYTEST_ARGS)
	@echo "Docker security tests complete!"

# =============================================================================
# DATABASE OPERATIONS
# =============================================================================

db-migrate: ## Run database migrations
	@echo "Running database migrations..."
	alembic upgrade head
	@echo "Database migrations complete!"

db-migrate-test: ## Run database migrations for test environment
	@echo "Running test database migrations..."
	$(DOCKER_COMPOSE_TEST) run --rm api alembic upgrade head
	@echo "Test database migrations complete!"

db-reset: ## Reset database (WARNING: This will delete all data)
	@echo "Resetting database..."
	alembic downgrade base
	alembic upgrade head
	@echo "Database reset complete!"

# =============================================================================
# DEVELOPMENT WORKFLOWS
# =============================================================================

dev-setup: ## Complete development environment setup
	@echo "Setting up development environment..."
	@echo "==================================="
	@make venv
	@make install-dev
	@make db-migrate
	@echo "Development environment setup complete!"

dev-test: ## Run development test suite
	@echo "Running development tests..."
	@make lint
	@make test-unit
	@make test-security-quick
	@echo "Development tests complete!"

dev-security: ## Run security checks for development
	@echo "Running development security checks..."
	@make security-lint
	@make test-security-auth
	@make test-security-validation
	@echo "Development security checks complete!"

# =============================================================================
# QUICK WORKFLOWS
# =============================================================================

quick-test: ## Quick test run for development
	@echo "Running quick tests..."
	pytest $(TEST_DIR) $(PYTEST_ARGS) -x --maxfail=3 -m "not slow"
	@echo "Quick tests complete!"

quick-security: ## Quick security validation
	@echo "Running quick security checks..."
	@make security-validate-quick
	@make test-security-auth
	@echo "Quick security checks complete!"

quick-deploy-check: ## Quick deployment validation
	@echo "Running quick deployment checks..."
	@make deploy-check-quick
	@make deploy-validate-config
	@echo "Quick deployment checks complete!"

# =============================================================================
# REPORTING AND DOCUMENTATION
# =============================================================================

report-security: ## Generate comprehensive security report
	@echo "Generating security report..."
	@make security-validate-report
	@make test-security --junit-xml=security-test-results.xml
	@echo "Security report generated!"

report-coverage: ## Generate test coverage report
	@echo "Generating coverage report..."
	pytest $(TEST_DIR) $(PYTEST_COV_ARGS) --cov-report=html --cov-report=xml
	@echo "Coverage report generated in htmlcov/"

report-performance: ## Generate performance test report
	@echo "Generating performance report..."
	pytest $(TEST_DIR)/performance $(PYTEST_ARGS) --benchmark-json=performance-report.json
	@echo "Performance report generated!"

# =============================================================================
# MAINTENANCE AND UPDATES
# =============================================================================

update-deps: ## Update dependencies
	@echo "Updating dependencies..."
	$(PIP) list --outdated
	$(PIP) install --upgrade -r requirements.txt
	@echo "Dependencies updated!"

security-audit: ## Run security audit of dependencies
	@echo "Running security audit..."
	safety check
	$(PIP) audit
	@echo "Security audit complete!"

# =============================================================================
# SPECIAL TARGETS
# =============================================================================

pre-commit: ## Run pre-commit checks
	@echo "Running pre-commit checks..."
	@make format
	@make lint
	@make quick-test
	@make quick-security
	@echo "Pre-commit checks complete!"

ci-pipeline: ## Full CI/CD pipeline simulation
	@echo "Running CI/CD pipeline..."
	@echo "========================"
	@make clean
	@make install
	@make lint
	@make security-lint
	@make test-ci
	@make security-validate
	@make deploy-check
	@echo "CI/CD pipeline complete!"

production-ready: ## Validate production readiness
	@echo "Validating production readiness..."
	@echo "================================="
	@make ci-pipeline
	@make test-all
	@make security-full
	@make deploy-prepare
	@make monitor-test
	@echo "Production readiness validation complete!"