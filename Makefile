VERSION ?= $(shell git describe --tags --abbrev=0 2>/dev/null || echo devel)
LDFLAGS := -X paepcke.de/pcscid.version=$(VERSION)

.PHONY: all build test fmt vet clean

all: build

build:
	go build -ldflags "$(LDFLAGS)" -o pcscid ./cmd/pcscid

test:
	go test ./...

fmt:
	gofmt -s -w .

vet:
	go vet ./...

clean:
	rm -f pcscid
