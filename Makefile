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
#	CGO_ENABLED=0 GOOS=linux GO111MODULE=on go build -a -ldflags '-extldflags "-static"' -o ./cmd/bin/gobmp ./cmd/gobmp/gobmp.go

topology:
	mkdir -p bin
	$(MAKE) -C ./cmd/topology compile-topology

container: gobmp
	docker build -t $(REGISTRY_NAME)/gobmp:$(IMAGE_VERSION) -f ./build/Dockerfile .

topology-container: topology
	docker build -t $(REGISTRY_NAME)/gobmp-topology:$(IMAGE_VERSION) -f ./build/Dockerfile.topology .

push: container
	docker push $(REGISTRY_NAME)/gobmp:$(IMAGE_VERSION)

topology-push: topology-container
	docker push $(REGISTRY_NAME)/gobmp-topology:$(IMAGE_VERSION)
	
clean:
	rm -rf bin

test:
	GO111MODULE=on go test `go list ./... | grep -v 'vendor'` $(TESTARGS)
	GO111MODULE=on go vet `go list ./... | grep -v vendor`
