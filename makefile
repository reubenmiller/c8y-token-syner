# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
APP_MAIN=./cmd/main/main.go
BINARY_NAME=c8y-starter
BINARY_UNIX=$(BINARY_NAME)_unix
VERSION_TAG=$(shell cat ./cumulocity.json | jq -r '.version')

all: test build

.PHONY: test
build:
	$(GOBUILD) -o $(BINARY_NAME) -v $(APP_MAIN)

.PHONY: test
test:
	$(GOTEST) -v ./pkg/app

clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_UNIX)

run:
	$(GOBUILD) -o $(BINARY_NAME) -v $(APP_MAIN)
	./$(BINARY_NAME)

deps:
	GO111MODULE=on $(GOMOD) download
	GO111MODULE=on $(GOMOD) vendor

prepare:
	chmod u+x ./build/microservice.sh

#
# Build all binaries for all platforms
#
PLATFORMS := windows linux darwin
os = $(word 1, $@)

.PHONY: $(PLATFORMS)
$(PLATFORMS):
	mkdir -p release
	GOOS=$(os) GOARCH=amd64 go build -o release/$(BINARY_NAME)-v$(VERSION_TAG)-$(os)-amd64 ./cmd/main/main.go

.PHONY: release-all
release-all: windows linux darwin

#
# Build everything
#
.PHONY: release
release:
	$(MAKE) prepare
	$(MAKE) clean-release
	$(MAKE) release-all -j3

#
# Build microservice zip file
#
build-microservice:
	$(MAKE) prepare
	$(MAKE) clean-release
	mkdir -p release
	./build/microservice.sh pack --directory ./ --name $(BINARY_NAME) --tag "$(VERSION_TAG)" && mv $(BINARY_NAME).zip release/$(BINARY_NAME)-v$(VERSION_TAG).zip

# Clean folder
.PHONY: clean-release
clean-release:
	rm -Rf release
