# Makefile for miekg/pkcs11 — PKCS #11 v3.2 support
#
# The three official OASIS PKCS #11 v3.2 headers are downloaded verbatim from
# the canonical OASIS publication URL. They must never be hand-edited.
# After any header refresh, re-run `make generate` to regenerate zconst.go.

OASIS := https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/include/pkcs11-v3.2

.PHONY: all headers generate test integration integration-v32 clean-headers

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

# ── Code generation ──────────────────────────────────────────────────────────
# zconst.go is generated from pkcs11t.h by the //go:generate directive.
# Must be re-run after `make headers` or `make refresh-headers`.
generate:
	go generate ./...

# ── Tests ────────────────────────────────────────────────────────────────────
test:
	go test ./...

# Integration tests use a single PKCS11_MODULE for both PKCS #11 v2.4 and v3.2.
#
# SoftHSMv3 (https://github.com/pqctoday/softhsmv3) is recommended because it
# implements v3.2 while remaining fully backward-compatible with v2.4.
# System-installed libsofthsm2.so also works; v3.2/PQC tests will self-skip.
#
# No external tools required — token initialisation is done entirely via the
# PKCS#11 API (C_InitToken / C_InitPIN).
#
# Build SoftHSMv3 from source:
#   git clone https://github.com/pqctoday/softhsmv3
#   cd softhsmv3
#   cmake -B build -DCMAKE_BUILD_TYPE=Release
#   cmake --build build -j$(nproc)
#
# Run all integration tests (v2.4 compat + v3.2):
#   make integration PKCS11_MODULE=$PWD/softhsmv3/build/src/lib/libsofthsmv3.so
#
# Run only v3.2/PQC tests:
#   make integration-v32 PKCS11_MODULE=$PWD/softhsmv3/build/src/lib/libsofthsmv3.so

PKCS11_MODULE ?=
PKCS11_PIN    ?= 1234

.PHONY: integration integration-v32

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
	    go test -v ./...

# Run only v3.2 and PQC tests (faster when iterating on new algorithms).
integration-v32:
	@if [ -z "$(PKCS11_MODULE)" ]; then \
	    echo "Error: PKCS11_MODULE is not set."; \
	    exit 1; \
	fi
	PKCS11_MODULE="$(PKCS11_MODULE)" PKCS11_PIN="$(PKCS11_PIN)" \
	    go test -v -run 'TestPQC|TestV32' ./...

# ── clean-headers ────────────────────────────────────────────────────────────
# Removes the downloaded OASIS headers (run `make headers` to restore them).
clean-headers:
	rm -f pkcs11t.h pkcs11f.h pkcs11.h
