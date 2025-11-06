# AI Security Log Analyzer Agent - Makefile

.PHONY: help install dev test clean docker build logs

# Default environment variables
export PORT ?= 8000
export REDIS_URL ?= redis://localhost:6379
export DB_URL ?= sqlite:///storage/db.sqlite

help: ## Show this help message
	@echo "AI Security Log Analyzer Agent"
	@echo "Available commands:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install: ## Install dependencies
	pip install -r requirements.txt

dev: install ## Start development server (make dev runs uvicorn app.api:app reload)
	python main.py init
	uvicorn app.api:app --reload --host 0.0.0.0 --port $(PORT)

test: ## Run tests with sample logs
	python -m pytest tests/ -v --tb=short

test-quick: ## Quick test with generated sample logs
	python example_logs.py
	python main.py process example_access.log
	python main.py process example_security.jsonl

clean: ## Clean up generated files
	rm -rf storage/db.sqlite storage/faiss_index*
	rm -rf __pycache__ */__pycache__ */*/__pycache__
	rm -rf .pytest_cache
	rm -f example_*.log example_*.jsonl

init: ## Initialize the system
	python main.py init

logs: ## View recent logs (requires running server)
	curl -s http://localhost:$(PORT)/incidents | jq '.[0:3]'

stats: ## Show system statistics
	curl -s http://localhost:$(PORT)/stats | jq .

docker: ## Build and run with Docker Compose
	docker-compose up --build

docker-logs: ## View docker logs
	docker-compose logs -f api

docker-down: ## Stop docker containers
	docker-compose down

build: ## Build Docker image
	docker build -t ai-security-analyzer .

# Development shortcuts
serve: dev ## Alias for dev

process-sample: ## Process sample log file
	python main.py process example_access.log --window 24

generate-samples: ## Generate sample log files
	python example_logs.py

# Testing with curl
test-api: ## Test API endpoints
	@echo "Testing health endpoint..."
	curl -s http://localhost:$(PORT)/health | jq .
	@echo "\nTesting stats endpoint..."
	curl -s http://localhost:$(PORT)/stats | jq .
	@echo "\nTesting incidents endpoint..."
	curl -s http://localhost:$(PORT)/incidents | jq '.[0:2]'

# Production commands
prod-install: ## Install production dependencies
	pip install -r requirements.txt --no-dev

prod-run: ## Run production server
	python main.py init
	uvicorn app.api:app --host 0.0.0.0 --port $(PORT) --workers 4

# Environment setup
env-check: ## Check environment variables
	@echo "PORT: $(PORT)"
	@echo "REDIS_URL: $(REDIS_URL)"
	@echo "DB_URL: $(DB_URL)"
	@echo "OPENAI_API_KEY: $${OPENAI_API_KEY:+<set>}"

# Quick demo
demo: generate-samples process-sample ## Generate samples and process them
	@echo "Demo complete! Check results at http://localhost:$(PORT)/incidents"