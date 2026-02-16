.PHONY: hooks lint format format-python format-docs lint-docs

hooks:
	pre-commit install

lint:
	pre-commit run --all-files

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
