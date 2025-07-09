.PHONY: fmt
fmt: ## Format Move contracts.
	movefmt --dir-path=contracts/ccip
	movefmt --dir-path=contracts/data-feeds
	movefmt --dir-path=contracts/large_packages
	movefmt --dir-path=contracts/managed_token
	movefmt --dir-path=contracts/managed_token_faucet
	movefmt --dir-path=contracts/mcms
	movefmt --dir-path=contracts/platform
	movefmt --dir-path=contracts/platform_secondary
	movefmt --dir-path=contracts/test

.PHONY: wrappers
wrappers: ## Generate wrappers for Move contracts.
	go generate ./gen.go

.PHONY: move-test
move-test: ## Run the Move tests.
	contracts/scripts/test.sh

.PHONY: gomods
gomods: ## Install gomods
	go install github.com/jmank88/gomods@v0.1.5

.PHONY: gomodtidy
gomodtidy: gomods
	gomods tidy