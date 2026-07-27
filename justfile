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

test:
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

# Confirm the oracle still builds, its tests pass, and go-jmapserver has not
# drifted from the revision this port was written against.
oracle-check: oracle
    cd oracle/go-jmapsmtp && go test ./...
    cd {{go_jmapserver}} && go test ./...
    @echo "--- go-jmapserver drift since {{oracle_rev}} ---"
    @cd {{go_jmapserver}} && git log --oneline {{oracle_rev}}..HEAD || true

# Differential test: oracle vs this port (PLAN.md M1).
difftest:
    cargo run -p xtask -- difftest

# Differential test with the oracle on BOTH sides — proves the normalisation
# filters strip only non-determinism. Must pass before difftest means anything.
difftest-selfcheck:
    cargo run -p xtask -- difftest --both-oracle
