GO ?= go
PYTHON ?= python3
BINARY := build/ueg
VERSION ?= 2.2.0-v3-candidate.1
LDFLAGS := -s -w -buildid= -X main.Version=$(VERSION)
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

.PHONY: all build test test-go test-cross vet fmt demo dist release verify-release clean

all: build

build:
	@mkdir -p build
	$(GO) build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/ueg

fmt:
	gofmt -w .

vet:
	$(GO) vet ./...

test: vet test-go test-cross

test-go:
	$(GO) test ./...

test-cross: build
	$(PYTHON) -m unittest discover -s tests -v

demo: build
	./demo/demo.sh

release: test dist

dist:
	$(PYTHON) tools/build_release.py --version $(VERSION) --output dist

verify-release:
	$(PYTHON) tools/verify_release.py dist

clean:
	rm -rf build dist
