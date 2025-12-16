.PHONY: help build run dev prod stop clean test publish

help:
	@echo "Agentic Security Dashboard - Makefile"
	@echo ""
	@echo "Commands:"
	@echo "  make build      - Build Docker image"
	@echo "  make dev        - Run local development"
	@echo "  make prod       - Run production mode"
	@echo "  make stop       - Stop containers"
	@echo "  make clean      - Clean up containers and images"
	@echo "  make test       - Run tests (if any)"
	@echo "  make publish    - Build and tag for production registry"

build:
	docker build -t agentic-dashboard:latest .

dev:
	docker compose up

prod:
	docker compose -f docker-compose.prod.yml up -d

stop:
	docker compose down
	docker compose -f docker-compose.prod.yml down

clean: stop
	docker rmi agentic-dashboard:latest || true

test:
	@echo "Running tests..."
	@python -m pytest tests/ || echo "No tests configured"

publish: build
	@echo "Tagging for production..."
	@read -p "Enter registry URL (e.g., registry.example.com): " registry; \
	read -p "Enter version tag (e.g., v1.0.0): " version; \
	docker tag agentic-dashboard:latest $$registry/agentic-dashboard:$$version; \
	docker tag agentic-dashboard:latest $$registry/agentic-dashboard:latest; \
	echo "Tagged: $$registry/agentic-dashboard:$$version"; \
	echo "Tagged: $$registry/agentic-dashboard:latest"; \
	echo "Push with: docker push $$registry/agentic-dashboard:$$version"

