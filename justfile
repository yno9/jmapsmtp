# Development tasks. `just --list` to see them.
#
# GO_JMAPSMTP / GO_JMAPSERVER point at the two Go repositories the oracle is
# built from. They live outside this repo on purpose — the oracle is a build
# product, never a checked-in copy (PLAN.md §2.3).

go_jmapsmtp   := env("GO_JMAPSMTP", home_dir() / "go-jmapsmtp")
go_jmapserver := env("GO_JMAPSERVER", home_dir() / "go-jmapserver")

# The commit the port is written against. Bumping this is a deliberate act:
# re-run `just oracle-check` and re-baseline the goldens (PLAN.md §8-A').
oracle_rev := "39a4d0e"

default:
    @just --list

build:
    cargo build --workspace

# The noanchor equivalent: `go build -tags noanchor ./...`
build-noanchor:
    cargo build --workspace --no-default-features

# Runs the Go interop tests for real. Plain `cargo test` skips them when the
# helper is absent (see crates/cryptenv/tests/interop.rs).
test: interop
    CRYPTENV_INTEROP=required STORE_INTEROP=required DISPATCH_INTEROP=required MIME_INTEROP=required DKIM_INTEROP=required AUTOCRYPT_INTEROP=required SMTP_INTEROP=required PGP_INTEROP=required DEVICES_INTEROP=required STARTUP_INTEROP=required cargo test --workspace

# Everything except the Go interop tests, for when the Go toolchain is absent.
test-rust-only:
    cargo test --workspace

lint:
    cargo clippy --workspace --all-targets -- -D warnings
    cargo fmt --all --check

fmt:
    cargo fmt --all

run:
    cargo run --bin jmapsmtp

# ── the Go reference implementation ───────────────────────────────────────

# Build the oracle into oracle/. Rewrites the `replace` directive that points
# at the original author's machine (/Users/n/go-jmapserver).
oracle:
    rm -rf oracle/go-jmapsmtp
    mkdir -p oracle
    cp -r {{go_jmapsmtp}} oracle/go-jmapsmtp
    rm -rf oracle/go-jmapsmtp/.git
    sed -i 's|=> /Users/n/go-jmapserver|=> {{go_jmapserver}}|' oracle/go-jmapsmtp/go.mod
    cd oracle/go-jmapsmtp && go build -o ../jmapsmtp-oracle .
    cd oracle/go-jmapsmtp && go build -tags noanchor -o ../jmapsmtp-oracle-noanchor .
    @echo "oracle built: oracle/jmapsmtp-oracle"

# Build the Go interop helpers used by the cross-implementation tests. They
# link the real Go packages inside the oracle checkout rather than a
# reimplementation, so they need `just oracle` to have run.
interop: oracle
    mkdir -p oracle/go-jmapsmtp/cmd/cryptenv-interop
    cp xtask/interop/cryptenv/main.go oracle/go-jmapsmtp/cmd/cryptenv-interop/main.go
    cd oracle/go-jmapsmtp && go build -o ../cryptenv-interop ./cmd/cryptenv-interop
    mkdir -p oracle/go-jmapsmtp/cmd/store-interop
    cp xtask/interop/store/main.go oracle/go-jmapsmtp/cmd/store-interop/main.go
    cd oracle/go-jmapsmtp && go build -o ../store-interop ./cmd/store-interop
    mkdir -p oracle/go-jmapsmtp/cmd/mime-interop
    cp xtask/interop/mime/main.go oracle/go-jmapsmtp/cmd/mime-interop/main.go
    cd oracle/go-jmapsmtp && go build -o ../mime-interop ./cmd/mime-interop
    mkdir -p oracle/go-jmapsmtp/cmd/dkim-interop
    cp xtask/interop/dkim/main.go oracle/go-jmapsmtp/cmd/dkim-interop/main.go
    cd oracle/go-jmapsmtp && go build -o ../dkim-interop ./cmd/dkim-interop
    mkdir -p oracle/go-jmapsmtp/cmd/autocrypt-interop
    cp xtask/interop/autocrypt/main.go oracle/go-jmapsmtp/cmd/autocrypt-interop/main.go
    cd oracle/go-jmapsmtp && go build -o ../autocrypt-interop ./cmd/autocrypt-interop
    mkdir -p oracle/go-jmapsmtp/cmd/smtp-interop
    cp xtask/interop/smtp/main.go oracle/go-jmapsmtp/cmd/smtp-interop/main.go
    cd oracle/go-jmapsmtp && go build -o ../smtp-interop ./cmd/smtp-interop
    mkdir -p oracle/go-jmapsmtp/cmd/pgp-interop
    cp xtask/interop/pgp/main.go oracle/go-jmapsmtp/cmd/pgp-interop/main.go
    cd oracle/go-jmapsmtp && go build -o ../pgp-interop ./cmd/pgp-interop
    @echo "interop helpers built"

# Confirm the oracle still builds, its tests pass, and go-jmapserver has not
# drifted from the revision this port was written against.
oracle-check: oracle
    cd oracle/go-jmapsmtp && go test ./...
    cd {{go_jmapserver}} && go test ./...
    @echo "--- go-jmapserver drift since {{oracle_rev}} ---"
    @cd {{go_jmapserver}} && git log --oneline {{oracle_rev}}..HEAD || true

# ── differential testing (PLAN.md M1) ─────────────────────────────────────

# Oracle vs this port. The acceptance criterion for M4 onwards.
difftest *ARGS:
    cargo run -p xtask -- difftest {{ARGS}}

# Oracle vs oracle. Proves the normalisation filters strip only genuine
# non-determinism; must pass before `difftest` means anything.
difftest-oracle *ARGS:
    cargo run -p xtask -- difftest --both-oracle {{ARGS}}

# Oracle vs a deliberately mutated oracle. Proves the harness can FAIL — a
# green difftest is worthless if a red one is unreachable.
difftest-selftest:
    cargo run -p xtask -- difftest --self-test

# Print the normalisation filters: the complete list of what the two
# implementations are allowed to disagree about.
difftest-filters:
    cargo run -p xtask -- difftest --show-filters

# Everything that must hold before the harness is trusted.
difftest-check: difftest-selftest difftest-oracle
