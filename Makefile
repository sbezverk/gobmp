REGISTRY_NAME?=docker.io/sbezverk
IMAGE_VERSION?=test-235

.PHONY: all gobmp player container push clean test lint gobmp-mac-arm64  gobmp-linux-arm64  gobmp-mac-amd64  cicd-image validator-mac-amd64 validator-mac-arm64 validator player-container validator-container player-push validator-push

ifdef V
TESTARGS = -v -args -alsologtostderr -v 5
else
TESTARGS =
endif

all: gobmp validator

gobmp:
	mkdir -p bin
	$(MAKE) -C ./cmd/gobmp compile-gobmp

gobmp-mac-arm64:
	mkdir -p bin
	$(MAKE) -C ./cmd/gobmp compile-gobmp-mac-arm64

gobmp-linux-arm64:
	mkdir -p bin
	$(MAKE) -C ./cmd/gobmp compile-gobmp-linux-arm64

cicd-image:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=$(shell go env GOARCH) GO111MODULE=on go build -a -ldflags '-extldflags "-static"' -o ./bin/gobmp ./cmd/gobmp/gobmp.go
	docker buildx build --platform linux/$(shell go env GOARCH) -t localhost/gobmp:cicd -f ./build/Dockerfile.gobmp --load .

gobmp-mac-amd64:
	mkdir -p bin
	$(MAKE) -C ./cmd/gobmp compile-gobmp-mac-amd64

player:
	mkdir -p bin
	$(MAKE) -C ./cmd/player compile-player

validator:
	mkdir -p bin
	$(MAKE) -C ./cmd/validator compile-validator

validator-mac-amd64:
	mkdir -p bin
	$(MAKE) -C ./cmd/validator compile-validator-mac-amd64

validator-mac-arm64:
	mkdir -p bin
	$(MAKE) -C ./cmd/validator compile-validator-mac-arm64

container: gobmp
	docker buildx build --platform linux/amd64 --load -t $(REGISTRY_NAME)/gobmp:$(IMAGE_VERSION) -f ./build/Dockerfile.gobmp .

player-container: player
	docker buildx build --platform linux/amd64 --load -t $(REGISTRY_NAME)/gobmp-player:$(IMAGE_VERSION) -f ./build/Dockerfile.player .

validator-container: validator
	docker buildx build --platform linux/amd64 --load -t $(REGISTRY_NAME)/gobmp-validator:$(IMAGE_VERSION) -f ./build/Dockerfile.validator .

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
