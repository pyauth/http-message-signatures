SHELL=/bin/bash

lint:
	ruff check http_message_signatures
	mypy --check-untyped-defs http_message_signatures

test: lint
	python -m unittest discover -s test -p 'test*.py' -v

init_docs:
	cd docs; sphinx-quickstart

docs:
	python -m sphinx -W --keep-going docs docs/html

release-docs:
	$(MAKE) docs
	-git branch -D gh-pages
	git checkout -B gh-pages-stage
	touch docs/html/.nojekyll
	git add --force docs/html
	git commit -m "Docs for ${TAG}"
	git push --force origin $$(git subtree split --prefix docs/html --branch gh-pages):refs/heads/gh-pages
	git checkout -

install:
	-rm -rf dist
	python -m build
	pip install --upgrade dist/*.whl

.PHONY: test lint release docs release-docs

include common.mk
