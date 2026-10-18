SHELL=/bin/bash

lint:
	ruff check http_message_signatures
	mypy --check-untyped-defs http_message_signatures

test: lint
	python ./test/test.py -v

init_docs:
	cd docs; sphinx-quickstart

docs:
	python -m sphinx -W --keep-going docs docs/html

install:
	-rm -rf dist
	python -m build
	pip install --upgrade dist/*.whl

.PHONY: test lint release docs

include common.mk
