REGISTRY_NAME?=docker.io/sbezverk
IMAGE_VERSION?=0.0.0

.PHONY: all gobmp topology container push clean test

ifdef V
TESTARGS = -v -args -alsologtostderr -v 5
else
TESTARGS =
endif

all: gobmp

gobmp:
	mkdir -p bin
	$(MAKE) -C ./cmd/gobmp compile-gobmp

topology:
	mkdir -p bin
	$(MAKE) -C ./cmd/topology compile-topology

player:
	mkdir -p bin
	$(MAKE) -C ./cmd/player compile-player

container: gobmp
	docker build -t $(REGISTRY_NAME)/gobmp:$(IMAGE_VERSION) -f ./build/Dockerfile .

topology-container: topology
	docker build -t $(REGISTRY_NAME)/gobmp-topology:$(IMAGE_VERSION) -f ./build/Dockerfile.topology .

player-container: player
	docker build -t $(REGISTRY_NAME)/gobmp-player:$(IMAGE_VERSION) -f ./build/Dockerfile.player .

push: container
	docker push $(REGISTRY_NAME)/gobmp:$(IMAGE_VERSION)

topology-push: topology-container
	docker push $(REGISTRY_NAME)/gobmp-topology:$(IMAGE_VERSION)

player-push: player-container
	docker push $(REGISTRY_NAME)/gobmp-player:$(IMAGE_VERSION)

clean:
	rm -rf bin

test:
	GO111MODULE=on go test `go list ./... | grep -v 'vendor'` $(TESTARGS)
	GO111MODULE=on go vet `go list ./... | grep -v vendor`
