#!/usr/bin/env bash
set -e

cargo test --locked --package payjoin-cli --verbose --all-features
