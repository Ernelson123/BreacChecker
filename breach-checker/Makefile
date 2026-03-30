.PHONY: build test clean install build-scanner build-scanner-release test-python test-go lint

build-scanner:
	cd scanner && go build -o breach-scanner .

build-scanner-release:
	cd scanner && CGO_ENABLED=0 go build -ldflags="-s -w" -o breach-scanner .

test-python:
	uv run pytest tests/ -v --cov=src/breach_checker

test-go:
	cd scanner && go test ./... -v

test: test-python test-go

install: build-scanner
	uv sync --extra dev

lint:
	uv run ruff check src/
	uv run mypy src/
	cd scanner && go vet ./...

clean:
	cd scanner && rm -f breach-scanner
	find . -name "__pycache__" -type d -exec rm -rf {} +
