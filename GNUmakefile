.PHONY: fmt
fmt: ## Format Move contracts.
	movefmt --dir-path=contracts/ccip
	movefmt --dir-path=contracts/data-feeds
	movefmt --dir-path=contracts/large_packages
	movefmt --dir-path=contracts/mcms
	movefmt --dir-path=contracts/platform
	movefmt --dir-path=contracts/test

.PHONY: wrappers
wrappers: ## Generate wrappers for Move contracts.
	go generate ./gen.go

.PHONY: move-test
move-test: ## Run the Move tests.
	contracts/scripts/test.sh

.PHONY: mockery
mockery: ## Install mockery.
	go install github.com/vektra/mockery/v2@v2.53.3

.PHONY: generate
generate: mockery
	mockery