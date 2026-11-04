# PYTHON can point at a virtualenv: make test PYTHON=.venv/bin/python
PYTHON ?= python3
RULE ?= detections/sigma/proc_creation_win_powershell_encoded_command.yml
RUN_ID ?= local-$(shell date +%s)
COMPOSE_ENV = HOST_UID=$(shell id -u) HOST_GID=$(shell id -g)

.PHONY: setup test lint validate validate-docker clean

setup:  ## Install development dependencies
	$(PYTHON) -m pip install -r requirements-dev.txt

test:  ## Run the unit tests and negative controls
	$(PYTHON) -m pytest

lint:  ## Lint the Sigma rules with sigma-cli
	$(PYTHON) -m sigma.cli.main check detections/sigma

validate:  ## Validate RULE with no Docker or server, using a JSON alerts file
	$(PYTHON) scripts/simulate_atomic.py --rule "$(RULE)" --run-id "$(RUN_ID)" --out reports/events.jsonl
	$(PYTHON) scripts/ship_events.py --rule "$(RULE)" --events reports/events.jsonl --run-id "$(RUN_ID)" --alerts-out reports/alerts.json
	$(PYTHON) scripts/validate_alert.py --rule "$(RULE)" --run-id "$(RUN_ID)" --alerts-file reports/alerts.json --report reports/report.json --summary reports/summary.md

validate-docker:  ## Validate RULE in the isolated containers, as CI does
	mkdir -p reports
	$(COMPOSE_ENV) docker compose up -d --build --wait siem
	$(COMPOSE_ENV) docker compose run --rm simulator python scripts/simulate_atomic.py --rule "$(RULE)" --run-id "$(RUN_ID)" --out reports/events.jsonl
	$(COMPOSE_ENV) docker compose run --rm runner python scripts/ship_events.py --rule "$(RULE)" --events reports/events.jsonl --run-id "$(RUN_ID)" --siem-url http://siem:8080
	$(COMPOSE_ENV) docker compose run --rm runner python scripts/validate_alert.py --rule "$(RULE)" --run-id "$(RUN_ID)" --siem-url http://siem:8080 --report reports/report.json --summary reports/summary.md

clean:  ## Stop the containers and delete reports
	docker compose down -v --remove-orphans
	rm -rf reports
