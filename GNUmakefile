.PHONY: fmt
fmt: ## Format Move contracts.
	movefmt --dir-path=contracts/ccip
	movefmt --dir-path=contracts/data-feeds
	movefmt --dir-path=contracts/large_packages
	movefmt --dir-path=contracts/managed_token
	movefmt --dir-path=contracts/managed_token_faucet
	movefmt --dir-path=contracts/mcms
	movefmt --dir-path=contracts/mcms_registrars
	movefmt --dir-path=contracts/platform
	movefmt --dir-path=contracts/platform_secondary
	movefmt --dir-path=contracts/regulated_token
	movefmt --dir-path=contracts/test
	movefmt --dir-path=contracts/test_token

.PHONY: wrappers
wrappers: ## Generate wrappers for Move contracts.
	go generate ./gen.go

.PHONY: move-test
move-test: ## Run the Move tests.
	contracts/scripts/test.sh

.PHONY: move-clean
move-clean: ## Cleans all Move build artifacts
	contracts/scripts/clean.sh

.PHONY: gomodtidy
gomodtidy: ## Run go mod tidy on all modules.
	go run github.com/jmank88/gomods@v0.1.7 tidy
