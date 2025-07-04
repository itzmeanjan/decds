# Collects inspiration from https://github.com/0xMiden/miden-base/blob/983357b2ad42f6e8d3c338d460a69479b99a1136/Makefile

.DEFAULT_GOAL := help

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: clippy
clippy: ## Runs clippy showing warnings
	cargo clippy --all-targets -- -D warnings

.PHONY: format
format: ## Formats source tree
	cargo fmt --all

.PHONY: test
test: ## Run all tests
	RUST_BACKTRACE=1 cargo test --profile test-release

.PHONY: coverage
coverage: ## Generates HTML code coverage report, using `cargo-tarpaulin`
	cargo tarpaulin -t 600 --profile test-release --out Html

.PHONY: clean
clean: ## Removes cargo target directory
	cargo clean
