BINARY := fnb
PKG := ./cmd/fnb
VERSION := $(shell grep '^MARKETING_VERSION=' version.env | cut -d= -f2)
LDFLAGS := -X github.com/yashiels/fnb/internal/cli.Version=$(VERSION)

.PHONY: build test scan lint vet fmt tidy clean

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) $(PKG)

test:
	go test ./...

scan:
	go test ./internal/fixturescan

vet:
	go vet ./...

fmt:
	gofmt -l -w .

lint: vet
	@files="$$(gofmt -l .)"; test -z "$$files" || { echo "gofmt needed:"; echo "$$files"; exit 1; }
	@echo "gofmt clean"

tidy:
	go mod tidy

clean:
	rm -f $(BINARY)
