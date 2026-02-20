REGISTRY_NAME?=docker.io/sbezverk
IMAGE_VERSION?=test-235

# Require Go 1.21+ (dependencies use stdlib maps/slices; go.mod specifies 1.24)
GO_VERSION_OK := $(shell go version 2>/dev/null | grep -qE 'go1\.(2[1-9]|[3-9][0-9])' && echo yes)
ifneq ($(GO_VERSION_OK),yes)
$(error Go 1.21 or later is required (go.mod specifies 1.24). You have: $(shell go version 2>/dev/null || echo "go not found"). See README for install instructions.)
endif

.PHONY: all gobmp player container push clean test lint

ifdef V
TESTARGS = -v -args -alsologtostderr -v 5
else
TESTARGS =
endif

all: gobmp validator

gobmp:
	mkdir -p bin
	$(MAKE) -C ./cmd/gobmp compile-gobmp

player:
	mkdir -p bin
	$(MAKE) -C ./cmd/player compile-player

validator:
	mkdir -p bin
	$(MAKE) -C ./cmd/validator compile-validator

validator-mac:
	mkdir -p bin
	$(MAKE) -C ./cmd/validator compile-validator-mac

container: gobmp
	docker build -t $(REGISTRY_NAME)/gobmp:$(IMAGE_VERSION) -f ./build/Dockerfile.gobmp .

player-container: player
	docker build -t $(REGISTRY_NAME)/gobmp-player:$(IMAGE_VERSION) -f ./build/Dockerfile.player .

validator-container: validator
	docker build -t $(REGISTRY_NAME)/gobmp-validator:$(IMAGE_VERSION) -f ./build/Dockerfile.validator .

push: container
	docker push $(REGISTRY_NAME)/gobmp:$(IMAGE_VERSION)

player-push: player-container
	docker push $(REGISTRY_NAME)/gobmp-player:$(IMAGE_VERSION)

validator-push: validator-container
	docker push $(REGISTRY_NAME)/gobmp-validator:$(IMAGE_VERSION)

clean:
	rm -rf bin

lint:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	golangci-lint run

test:
	GO111MODULE=on go test `go list ./... | grep -v 'vendor'` $(TESTARGS)
	GO111MODULE=on go vet `go list ./... | grep -v vendor`
