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

# The malformed-file sweep over the whole corpus rather than the eight
# files t/run.sh samples. Six minutes, most of it in capinfos and tshark.
hostile: all
	HOSTILE_FILES="$$(ls t/corpus/hand/* t/corpus/live/*.pcap)" \
	HOSTILE_ORACLE_EVERY=25 ./t/run.sh

vet:
	$(GO) vet ./...

clean:
	rm -f pcapd
	rm -rf t/corpus t/tmp.*

.PHONY: all test hostile vet clean
