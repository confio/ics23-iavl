.PHONY: build test testgen

# make sure we turn on go modules
export GO111MODULE := on

build:
	go build ./cmd/testgen-iavl

test:
	go test .

testgen:
	go run ./cmd/testgen-iavl