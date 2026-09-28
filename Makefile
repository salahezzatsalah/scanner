.PHONY: help install bootstrap test lint fmt doctor clean

help:
	@echo "install    - install package + dev dependencies"
	@echo "bootstrap  - install the Go scanner binaries and nuclei templates"
	@echo "doctor     - report which external tools are available"
	@echo "test       - run the test suite"
	@echo "lint       - ruff check"
	@echo "fmt        - ruff format"
	@echo "clean      - remove caches and build artifacts"

install:
	python3 -m pip install -e ".[dev]"

bootstrap:
	./scripts/bootstrap.sh

doctor:
	reconx doctor

test:
	python3 -m pytest -q

lint:
	python3 -m ruff check src tests

fmt:
	python3 -m ruff format src tests
	python3 -m ruff check --fix src tests

clean:
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
