# Common development tasks for WatchMe.
# Prefer -j1 for cargo to avoid overloading the machine.

set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

fmt:
    cargo fmt

fmt-check:
    cargo fmt --check

clippy:
    cargo clippy --all-targets --all-features -j1 -- -D warnings

test:
    cargo test --all-features -j1 --locked

test-release-scripts:
    scripts/test-reconcile-release.sh

install-smoke:
    cargo test --test install_smoke -j1 --locked

build-release:
    cargo build --release -j1 --locked

schemas:
    bash scripts/validate-schemas.sh

bench:
    bash scripts/benchmark-idle.sh --watchers 0 --duration 35 --poll 15
    bash scripts/benchmark-idle.sh --watchers 1 --duration 35 --poll 15
    bash scripts/benchmark-idle.sh --watchers 10 --duration 35 --poll 15

bench-quick:
    WATCHME_BENCH_DURATION=10 bash scripts/benchmark-idle.sh --watchers 0 --duration 10 --poll 5

install prefix="$HOME/.local":
    bash scripts/install.sh --prefix {{prefix}} --build --with-completions --with-man

uninstall prefix="$HOME/.local":
    bash scripts/uninstall.sh --prefix {{prefix}}

gates: fmt-check clippy test build-release schemas install-smoke
    @echo "core gates passed; run 'just bench' for idle benchmarks"
