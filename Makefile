.DEFAULT_GOAL := test

GOPATH := $(shell go env GOPATH)

lint:
	golangci-lint run .

test: lint
	go test -v -cover -covermode atomic -coverprofile profile.out .

install_linter:
	curl -sfL https://install.goreleaser.com/github.com/golangci/golangci-lint.sh | sh -s -- -b $(GOPATH)/bin v1.12.5

.PHONY: test
