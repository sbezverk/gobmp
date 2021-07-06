REGISTRY_NAME?=docker.io/codebgp
IMAGE_VERSION?=0.0.1

.PHONY: all gobmp player container push clean test

ifdef V
TESTARGS = -v -args -alsologtostderr -v 5
else
TESTARGS =
endif

all: gobmp

gobmp:
	mkdir -p bin
	$(MAKE) -C ./cmd/gobmp compile-gobmp

player:
	mkdir -p bin
	$(MAKE) -C ./cmd/player compile-player

container: gobmp
	docker build -t $(REGISTRY_NAME)/gobmp:$(IMAGE_VERSION) -f ./build/Dockerfile.gobmp .

player-container: player
	docker build -t $(REGISTRY_NAME)/gobmp-player:$(IMAGE_VERSION) -f ./build/Dockerfile.player .

push: container
	docker push $(REGISTRY_NAME)/gobmp:$(IMAGE_VERSION)

player-push: player-container
	docker push $(REGISTRY_NAME)/gobmp-player:$(IMAGE_VERSION)

clean:
	rm -rf bin

test:
	GO111MODULE=on go test `go list ./... | grep -v 'vendor'` $(TESTARGS)
	GO111MODULE=on go vet `go list ./... | grep -v vendor`
