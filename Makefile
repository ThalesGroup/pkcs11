# Makefile for miekg/pkcs11 — PKCS #11 v3.2 support
#
# The three official OASIS PKCS #11 v3.2 headers are downloaded verbatim from
# the canonical OASIS publication URL. They must never be hand-edited.
# After any header refresh, re-run `make generate` to regenerate zconst.go.

OASIS := https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/include/pkcs11-v3.2

.PHONY: all headers generate test integration clean

all: headers generate test

# ── Download official OASIS headers ──────────────────────────────────────────
headers: pkcs11t.h pkcs11f.h pkcs11.h

pkcs11t.h:
	curl -sSfL "$(OASIS)/pkcs11t.h" -o $@

pkcs11f.h:
	curl -sSfL "$(OASIS)/pkcs11f.h" -o $@

pkcs11.h:
	curl -sSfL "$(OASIS)/pkcs11.h" -o $@

# Force re-download even when files already exist
.PHONY: refresh-headers
refresh-headers:
	curl -sSfL "$(OASIS)/pkcs11t.h" -o pkcs11t.h
	curl -sSfL "$(OASIS)/pkcs11f.h" -o pkcs11f.h
	curl -sSfL "$(OASIS)/pkcs11.h"  -o pkcs11.h
	@echo "Refreshed all three official OASIS v3.2 headers."

# ── Code generation ───────────────────────────────────────────────────────────
# zconst.go is generated from pkcs11t.h by the //go:generate directive.
# Must be re-run after `make headers` or `make refresh-headers`.
generate:
	go generate ./...

# ── Tests ─────────────────────────────────────────────────────────────────────
test:
	go test ./...

# Integration tests require SoftHSMv3 (https://github.com/pqctoday/softhsmv3)
# which is the only publicly available software token that implements v3.2.
#
# Build SoftHSMv3:
#   git clone https://github.com/pqctoday/softhsmv3
#   cd softhsmv3
#   cmake -B build -DCMAKE_BUILD_TYPE=Release
#   cmake --build build -j$(nproc)
#
# Initialise a token:
#   ./build/src/bin/softhsm2-util \
#       --init-token --slot 0 --label pkcs11test \
#       --pin 1234 --so-pin 12345678
#
# Then run:
#   make integration \
#       PKCS11_MODULE=/path/to/softhsmv3/build/src/lib/libsofthsmv3.so \
#       PKCS11_PIN=1234

PKCS11_MODULE ?=
PKCS11_PIN    ?= 1234

integration:
	@if [ -z "$(PKCS11_MODULE)" ]; then \
	    echo ""; \
	    echo "Error: PKCS11_MODULE is not set."; \
	    echo ""; \
	    echo "Example:"; \
	    echo "  make integration PKCS11_MODULE=/path/to/libsofthsmv3.so"; \
	    echo ""; \
	    exit 1; \
	fi
	PKCS11_MODULE="$(PKCS11_MODULE)" PKCS11_PIN="$(PKCS11_PIN)" \
	    go test -v -run TestML ./...

# ── Clean ─────────────────────────────────────────────────────────────────────
# Removes the downloaded OASIS headers (run `make headers` to restore them).
clean:
	rm -f pkcs11t.h pkcs11f.h pkcs11.h
