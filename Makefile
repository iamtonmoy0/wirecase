GO ?= go
BINARY ?= wirecase

.PHONY: build check

build:
	$(GO) build -trimpath -o $(BINARY) .

check:
	$(GO) build ./...

