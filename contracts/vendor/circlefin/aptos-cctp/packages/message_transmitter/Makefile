.PHONY: print-coverage test coverage compile publish publish-extension

print-coverage:
	@if [ ! -f .coverage_map.mvcov ]; then $(MAKE) coverage; fi;
	aptos move coverage source --module $(word 2,$(MAKECMDGOALS))  --dev

test:
	aptos move test --dev

coverage:
	aptos move test --coverage --dev

compile:
	aptos move compile --named-addresses message_transmitter=message_transmitter,aptos_extensions=aptos_extensions

publish:
	aptos move publish --profile $(profile) --named-addresses message_transmitter=message_transmitter,aptos_extensions=aptos_extensions --assume-yes

publish-extensions:
	aptos move publish --profile $(profile) --named-addresses message_transmitter=message_transmitter,aptos_extensions=aptos_extensions --assume-yes --package-dir ../../stablecoin-aptos/packages/aptos_extensions

# Prevents make from thinking the arguments are actual targets
%:
	@:
