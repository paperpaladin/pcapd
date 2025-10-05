# pcapd -- pcap/pcapng reader and TCP stream reassembler.
#
# Standard library only. GOPROXY is off so that a stray third-party import
# fails the build here instead of quietly fetching something.
GO      ?= go
GOFLAGS ?=
export GOPROXY = off
export GOTOOLCHAIN = local

all: pcapd

pcapd: $(wildcard *.go) go.mod
	$(GO) build $(GOFLAGS) -trimpath -o pcapd .

test: all
	./t/run.sh

vet:
	$(GO) vet ./...

clean:
	rm -f pcapd
	rm -rf t/corpus t/tmp.*

.PHONY: all test vet clean
