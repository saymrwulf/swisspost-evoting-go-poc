# Build orchestration for the evote PoC.
#
# The transport-security layer (Ed25519 signatures, X25519 ECDH) is implemented
# in Rust and linked into Go via cgo. `make rust` must run before `go build`,
# because pkg/transportsec links against rust/transportsec/target/release/libtransportsec.a.

RUST_DIR := rust/transportsec
RUST_LIB := $(RUST_DIR)/target/release/libtransportsec.a

.PHONY: all build rust test clean demo

all: build

# Build the Rust static library consumed by cgo.
rust: $(RUST_LIB)

$(RUST_LIB):
	cd $(RUST_DIR) && cargo build --release

# Build the Go binary (requires the Rust lib first).
build: rust
	go build -o evote ./cmd/evote

# Run the full test suite (Rust + Go, including the FFI round-trip).
test: rust
	cd $(RUST_DIR) && cargo test --release
	go test ./...

demo: build
	./evote demo --voters=10 --options=3

clean:
	rm -f evote
	cd $(RUST_DIR) && cargo clean
