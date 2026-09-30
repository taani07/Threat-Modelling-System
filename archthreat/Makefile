.PHONY: install test lint labs labs-solution eval demo clean

install:
	python3 -m venv .venv && . .venv/bin/activate && pip install -U pip && pip install -e ".[dev]"

test:
	pytest

lint:
	ruff check src tests labs && ruff format --check src tests

labs:
	pytest labs

labs-solution:
	LAB_SOLUTION=1 pytest labs

eval:
	archthreat eval

demo:
	archthreat analyze samples/rag-assistant.yaml
	archthreat report samples/payments-platform.yaml --out threat-model.md
	archthreat diff samples/payments-platform.yaml samples/payments-platform-v2.yaml
	archthreat sarif samples/payments-platform.yaml --out threats.sarif
	@echo "Open threat-model.md"

clean:
	rm -rf .archthreat threat-model.md threats.sarif assets.yaml .pytest_cache .ruff_cache
