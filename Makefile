.PHONY: build wasm publish test run-dev demo clean

build:
	mkdir -p bin && CGO_ENABLED=0 go build -o bin/ ./cmd/...

WORKLOADS := csv-stats hash-bytes primes

wasm:
	mkdir -p build
	for w in $(WORKLOADS); do GOOS=wasip1 GOARCH=wasm go build -o build/$$w.wasm ./workloads/$$w || exit 1; done

# Local dev only: generates a throwaway publisher key and signs the sample workloads.
publish: build wasm
	@test -f .trustgate-dev/publisher.key || (mkdir -p .trustgate-dev && bin/trustgate keygen -out .trustgate-dev/publisher)
	bin/trustgate publish -key .trustgate-dev/publisher.key -wasm build/csv-stats.wasm \
		-name csv-stats -version 1 -desc "Summary stats, per-group sums and z>3 anomalies over a CSV column" \
		-max-memory-mb 256 -max-timeout-ms 20000 -out registry/manifests
	bin/trustgate publish -key .trustgate-dev/publisher.key -wasm build/hash-bytes.wasm \
		-name hash-bytes -version 1 -desc "Length and SHA-256 of arbitrary binary stdin" \
		-max-memory-mb 256 -max-timeout-ms 20000 -out registry/manifests
	bin/trustgate publish -key .trustgate-dev/publisher.key -wasm build/primes.wasm \
		-name primes -version 1 -desc "Count primes below N with a sieve (CPU-heavy, for async jobs)" \
		-max-memory-mb 512 -max-timeout-ms 120000 -out registry/manifests

test:
	go test -count=1 ./...

# INSECURE dev mode: software attestation only, no enclave.
run-dev: publish
	bin/trustgate-server -mode dev -publisher-pub-file .trustgate-dev/publisher.pub -registry registry/manifests

demo:
	scripts/demo-local.sh

clean:
	rm -rf bin build .trustgate-dev registry/manifests

# ---- Nitro (run on the enclave-enabled parent instance) ----
.PHONY: eif run-enclave forwarder
eif:
	docker build -t trustgate:nitro -f Dockerfile.nitro .
	nitro-cli build-enclave --docker-uri trustgate:nitro --output-file build/trustgate.eif | tee build/trustgate.pcrs.json

# Never add --debug-mode here: it zeroes PCRs in attestation documents.
run-enclave:
	nitro-cli run-enclave --cpu-count 2 --memory 3072 --eif-path build/trustgate.eif --enclave-cid 16

forwarder:
	bin/vsock-forwarder -listen :8443 -cid 16 -port 8080
