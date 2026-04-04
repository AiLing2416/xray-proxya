BINARY_NAME=xray-proxya
BUILD_DIR=build
GO_ENV=CGO_ENABLED=0

all: clean build-arm64 build-amd64

build-arm64:
	$(GO_ENV) GOOS=linux GOARCH=arm64 go build -ldflags "-s -w -extldflags '-static'" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/xray-proxya

build-amd64:
	$(GO_ENV) GOOS=linux GOARCH=amd64 go build -ldflags "-s -w -extldflags '-static'" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/xray-proxya

clean:
	rm -rf $(BUILD_DIR)

test:
	go test ./...

.PHONY: all build-arm64 build-amd64 clean test
