#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 urtorrent contributors
#
# Regenerates the README badges with shields.io's badge-maker (needs Node).
# Version and MSRV come from the workspace Cargo.toml; run after a release bump:
#
#   docs/badges/generate.sh
set -euo pipefail

cd "$(dirname "$0")"
root=../..
version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$root/Cargo.toml" | head -1)
msrv=$(sed -n 's/^rust-version = "\(.*\)"/\1/p' "$root/Cargo.toml" | head -1)

badge() { # file label message color
    npx --yes -p badge-maker@6.0.0 badge "$2" "$3" "$4" @flat >"$1.svg"
}

badge crates-io  crates.io   "v$version"                     '#e6772e'
badge license    license     Apache-2.0                      '#3a72b0'
badge msrv       rust        "$msrv+"                        '#a72145'
badge platform   platform    'Linux · io_uring · kernel 6.1+' '#2b2b2b'
badge network    network     'IPv4 + IPv6'                   '#2e8b57'
badge transports transports  'TCP · uTP · MSE'               '#5a4fcf'
badge discovery  discovery   'trackers · DHT · PEX · LSD'    '#7a5c00'
badge oracle     wire-compat 'qBittorrent 5.2.3 / lt 2.0.14' '#2f6db5'
