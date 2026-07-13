.PHONY: install test quality benchmark demo serve docker-build

PYTHON ?= python3
export PYTHONPATH := src
export PYTHONDONTWRITEBYTECODE := 1

install:
	$(PYTHON) -m pip install --disable-pip-version-check -r requirements-build.lock -r requirements-dev.lock
	$(PYTHON) -m pip install --disable-pip-version-check --no-build-isolation --no-deps -e .

test:
	coverage run -m unittest discover -s tests -t . -v
	coverage report

quality:
	ruff check src tests scripts
	ruff format --check src tests scripts
	mypy src/cloud_breach_reconstructor
	$(PYTHON) -m compileall -q src tests scripts
	$(PYTHON) scripts/quality_gate.py

benchmark:
	$(PYTHON) -m cloud_breach_reconstructor benchmark datasets/lab/events.jsonl --truth datasets/lab/ground-truth.json --iterations 100

demo:
	$(PYTHON) -m cloud_breach_reconstructor analyze datasets/lab/events.jsonl --output reports/demo

serve:
	$(PYTHON) -m cloud_breach_reconstructor serve --host 127.0.0.1 --port 8080

docker-build:
	docker build --tag cloud-breach-reconstructor:local .
