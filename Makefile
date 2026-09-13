.PHONY: help build shell clean-output structure

help:
	@echo "Available targets: help build shell clean-output structure"

build:
	docker compose build

shell:
	docker compose run --rm research

clean-output:
	@find output -mindepth 1 ! -name .gitkeep -delete

structure:
	@find . -path './.git' -prune -o -maxdepth 3 -print | sort
