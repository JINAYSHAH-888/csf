SHELL := /bin/bash
GO ?= go
GATEWAY := ./gateway

.PHONY: help fmt vet test test-race cover bench security-test ci clean

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n",$$1,$$2}'

fmt: ## Format Go sources
	cd $(GATEWAY) && gofmt -w .

vet: ## Static analysis
	cd $(GATEWAY) && $(GO) vet ./...

test: ## Unit tests
	cd $(GATEWAY) && $(GO) test ./... -count=1

test-race: ## Unit tests under the race detector
	cd $(GATEWAY) && $(GO) test ./... -race -count=1

cover: ## Coverage report
	cd $(GATEWAY) && $(GO) test ./... -coverprofile=coverage.out -count=1 && $(GO) tool cover -func=coverage.out | tail -1

bench: ## Benchmarks (records host CPU)
	cd $(GATEWAY) && $(GO) test ./... -bench=. -benchmem -run=XXX

security-test: ## Security gates. Must be 100% green.
	cd $(GATEWAY) && $(GO) test ./internal/jwtverify/ -v -count=1 -run 'TestJWTAttackSuite|TestConfigRejects|TestOnlyOneParseCallSite|TestResultNeverCarriesRawToken'

ci: fmt vet test-race cover security-test ## Everything CI runs

clean:
	cd $(GATEWAY) && rm -f coverage.out
