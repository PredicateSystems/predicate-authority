.PHONY: hooks lint test examples verify-release-order build-packages format format-python format-docs lint-docs dev-install tag-release

dev-install:
	python -m pip install -e predicate_contracts -e predicate_authority

tag-release:
	@test -n "$(VERSION)" || (echo "Usage: make tag-release VERSION=X.Y.Z" && exit 1)
	python scripts/validate_release_tag.py --tag "v$(VERSION)"
	git tag -a "v$(VERSION)" -m "Release v$(VERSION)"
	@echo "Created tag v$(VERSION). Push with: git push origin v$(VERSION)"

hooks:
	pre-commit install

lint:
	pre-commit run --all-files

test:
	python -m pytest -q

examples:
	PYTHONPATH=. python examples/browser_guard_example.py
	PYTHONPATH=. python examples/mcp_tool_guard_example.py
	PYTHONPATH=. python examples/outbound_http_guard_example.py

verify-release-order:
	python scripts/verify_release_order.py

build-packages:
	python -m build predicate_contracts
	python -m build predicate_authority

format: format-python format-docs

format-python:
	pre-commit run black --all-files
	pre-commit run isort --all-files
	pre-commit run pyupgrade --all-files

format-docs:
	pre-commit run trailing-whitespace --all-files
	pre-commit run end-of-file-fixer --all-files
	pre-commit run mixed-line-ending --all-files

lint-docs:
	pre-commit run markdownlint-cli2
