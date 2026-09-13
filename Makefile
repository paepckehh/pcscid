PROJECT=$(shell basename $(CURDIR))
VERSION ?= $(shell git describe --tags --abbrev=0 2>/dev/null || echo v0.0.0-dev)
LDFLAGS := -X paepcke.de/$(PROJECT).version=$(VERSION)

all: info

info:
	@echo "$(PROJECT) $(VERSION)"

build:
	go build -ldflags "$(LDFLAGS)" -o $(PROJECT) ./cmd/$(PROJECT)

update:
	git pull
	git pull --tags

push: update
	git push
	git push --tags

deps:
	rm -rf go.mod go.sum
	go mod init paepcke.de/$(PROJECT)
	go mod tidy -v
	git config core.fileMode false

check:
	gofmt -l .
	go vet ./...
	go mod tidy -diff

test:
	go test -count=1 -parallel $$(nproc) -p $$(nproc) ./...

.PHONY: all info build update push deps check test