// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Prints the running kernel's io_uring feature support and exits non-zero if
//! the required baseline is missing. `xtask doctor` runs this.

extern crate urtorrent_uring as uring;

fn main() -> std::process::ExitCode {
    match uring::probe() {
        Ok(f) => {
            println!("{}", f.summary());
            if let Err(e) = f.require_baseline() {
                eprintln!("{e}");
                return std::process::ExitCode::FAILURE;
            }
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::ExitCode::FAILURE
        }
    }
}
