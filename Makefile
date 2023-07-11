REGISTRY_NAME?=docker.io/sbezverk
IMAGE_VERSION?=0.0.0

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
	$(MAKE) -C ./cmd/player compile-validator

container: gobmp
	docker build -t $(REGISTRY_NAME)/gobmp:$(IMAGE_VERSION) -f ./build/Dockerfile.gobmp .

player-container: player
	docker build -t $(REGISTRY_NAME)/gobmp-player:$(IMAGE_VERSION) -f ./build/Dockerfile.player .

validator-container: player
	docker build -t $(REGISTRY_NAME)/gobmp-player:$(IMAGE_VERSION) -f ./build/Dockerfile.validator .

push: container
	docker push $(REGISTRY_NAME)/gobmp:$(IMAGE_VERSION)

player-push: player-container
	docker push $(REGISTRY_NAME)/gobmp-player:$(IMAGE_VERSION)

validator-push: player-container
	docker push $(REGISTRY_NAME)/gobmp-validator:$(IMAGE_VERSION)

clean:
	rm -rf bin

lint:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	golangci-lint run

test:
	GO111MODULE=on go test `go list ./... | grep -v 'vendor'` $(TESTARGS)
	GO111MODULE=on go vet `go list ./... | grep -v vendor`
