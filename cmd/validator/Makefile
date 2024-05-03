compile-validator:
	CGO_ENABLED=0 GOOS=linux GO111MODULE=on go build -a -ldflags '-extldflags "-static"' -o ../../bin/validator ./validator.go

compile-validator-mac:
	CGO_ENABLED=0 GOOS=darwin GO111MODULE=on go build -a -ldflags '-extldflags "-static"' -o ../../bin/validator.mac ./validator.go
