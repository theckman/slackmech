.DEFAULT_GOAL := test

test:
	go test -v -covermode=count -coverprofile=profile.out .

.PHONY: test
