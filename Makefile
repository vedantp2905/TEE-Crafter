.PHONY: install test test-unit test-integration lint clean docker-build-cli docker-build-cli-multi help

DOCKER_CLI_IMAGE ?= $(USER)/tee-crafter:latest
DOCKER_CLI_LOCAL  ?= tee-crafter
DOCKER_MULTI_PLATFORMS ?= linux/amd64,linux/arm64

help:
	@echo "Usage: make <target>"
	@echo "Targets:"
	@echo "  install              Install dependencies into ./venv"
	@echo "  test                 Run unit tests (alias for test-unit)"
	@echo "  test-unit            Run the same suite CI runs: apps/cli/tests minus"
	@echo "                       anything marked 'integration'"
	@echo "  test-integration     Run tests/integration + anything marked"
	@echo "                       'integration' (may need cloud creds)"
	@echo "  lint                 Run the same ruff check CI runs, over src and tests"
	@echo "  clean                Remove build artifacts and caches"
	@echo "  docker-build-cli     Build the lean CLI image locally"
	@echo "  docker-build-cli-multi  Build/push multi-arch CLI image"
	@echo "  help                 Show this help message"

install:
	rm -rf venv
	python3.12 -m venv venv
	./venv/bin/pip install --upgrade pip
	./venv/bin/pip install -e "apps/cli[dev]"

test: test-unit

# Must stay identical to the command in .github/workflows/ci.yml, so that a
# green `make test` means a green CI run.  The previous recipe selected
# tests/cli + tests/core by path, which is NOT the same set: it missed the 33
# tests under tests/integration/ (none of which carry the marker, so CI does
# run them) and it did run the 7 cases that DO carry @pytest.mark.integration
# (all of which live in tests/cli + tests/core, so CI skips them).
test-unit:
	./venv/bin/python -m pytest apps/cli/tests -m "not integration" -o addopts= -q

# The `integration` marker and the tests/integration/ directory are two
# different things and they do not line up: the marker is on 7 cases in
# tests/cli + tests/core, while tests/integration/ holds 33 unmarked ones.
# This target runs both, which is what "the tests that may need cloud creds"
# actually means today.
test-integration:
	./venv/bin/python -m pytest apps/cli/tests/integration -o addopts= -q
	./venv/bin/python -m pytest apps/cli/tests -m integration -o addopts= -q

# Must stay identical to the `ruff check` command in .github/workflows/ci.yml,
# for the same reason test-unit must: a green `make lint` should mean a green
# Lint job. It did not. This ran pyflakes over src/ only, which differs from CI
# twice over — pyflakes is not ruff and applies none of the ruleset in
# apps/cli/pyproject.toml, and it never looked at tests/, where all nine of the
# errors CI was actually failing on lived. So `make lint` exited non-zero on
# harmless re-export warnings while the job it was supposed to predict was red
# for unrelated reasons.
lint:
	./venv/bin/python -m ruff check apps/cli/src apps/cli/tests

clean:
	rm -rf builds/
	find . -type d -name "__pycache__" -exec rm -r {} +
	find . -type d -name "*.egg-info" -exec rm -r {} +
	find . -type f -name "*.pyc" -exec rm {} +
	find . -type d -name ".pytest_cache" -exec rm -r {} +
	find . -type f -name "*.DS_Store" -exec rm {} +
	find . -type d -name ".tee-crafter-cache" -exec rm -r {} +

docker-build-cli:
	docker buildx build --load -t $(DOCKER_CLI_LOCAL) -f apps/cli/Dockerfile apps/cli

docker-build-cli-multi:
	docker buildx build --platform $(DOCKER_MULTI_PLATFORMS) -t $(DOCKER_CLI_IMAGE) -f apps/cli/Dockerfile --push apps/cli
