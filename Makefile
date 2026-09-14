PROJECT=$(shell basename $(CURDIR))
VERSION ?= $(shell git describe --tags --abbrev=0 2>/dev/null || echo v0.0.0-dev)
LDFLAGS := -X paepcke.de/$(PROJECT).version=$(VERSION)

all: info

info:
	@echo "$(PROJECT) $(VERSION)"

build:
	touch $(PROJECT) && rm $(PROJECT)
	go build -ldflags "$(LDFLAGS)" -o $(PROJECT) ./cmd/$(PROJECT)

update:
	git pull
	git pull --tags

push: update
	git push
	git push --tags

deploy-test-nix: update build 
	sudo -v
	sudo systemctl stop $(PROJECT).service || true
	sudo mkdir -p /nix/persist/bin || true
	sudo touch /nix/persist/bin/$(PROJECT)-pilot || true
	sudo cp -af /nix/persist/root/bin/$(PROJECT).old /nix/persist/root/bin/$(PROJECT).old2 || true 
	sudo cp -af /nix/persist/root/bin/$(PROJECT) /nix/persist/root/bin/$(PROJECT).old || true 
	sudo mv -f ./$(PROJECT) /nix/persist/root/bin/$(PROJECT) || true
	sudo systemctl start $(PROJECT).service

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
