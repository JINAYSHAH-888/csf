SHELL := /bin/bash
VENV := ../.venv/bin

.PHONY: help fmt lint type test cover security-test bench ci clean run

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n",$$1,$$2}'

fmt: ## Auto-fix formatting and imports
	$(VENV)/ruff check --fix csf/ tests/
	$(VENV)/ruff format csf/ tests/

lint: ## Lint
	$(VENV)/ruff check csf/ tests/

type: ## Strict type check
	$(VENV)/mypy -p csf

test: ## Unit + integration tests
	$(VENV)/python -m pytest tests/ -q

cover: ## Coverage report
	$(VENV)/python -m pytest tests/ -q --cov=csf --cov-report=term-missing

security-test: ## Security gates. Must be 100% green.
	$(VENV)/python -m pytest tests/test_jwt_attack_suite.py tests/test_framing.py -v

bench: ## Component benchmarks (records host CPU)
	$(VENV)/python scripts/bench.py

run: ## Run the gateway in shadow mode against a local upstream
	$(VENV)/python -m csf.main --upstream http://127.0.0.1:3000 --mode shadow

ci: lint type test cover security-test ## Everything CI runs

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage
	find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
