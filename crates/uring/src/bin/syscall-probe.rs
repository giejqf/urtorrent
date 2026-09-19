// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! A self-contained data-path exercise used by `cargo xtask syscalls`: it runs
//! a loopback TCP echo and a file read/write/fsync round-trip entirely through
//! io_uring. Both endpoints are uring tasks, so a correct build issues only
//! `io_uring_enter` for data transfer — never `epoll_*`, `poll`, `select`, or
//! off-ring socket/file syscalls. `xtask syscalls` runs this under strace and
//! fails if any banned syscall appears.

#![allow(clippy::unwrap_used)]

use std::process::ExitCode;

use uring::{Buffer, File, Runtime, TcpListener, TcpStream, spawn};

fn main() -> ExitCode {
    let rt = match Runtime::with_defaults() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("probe: {e}");
            return ExitCode::FAILURE;
        }
    };
    let ok = rt.block_on(async {
        // TCP echo, both ends on the ring.
        let listener = TcpListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = listener.local_addr();
        let server = spawn(async move {
            let conn = listener.accept().await.unwrap();
            let (r, buf) = conn.recv(Buffer::from_vec(vec![0u8; 256])).await;
            let n = r.unwrap() as usize;
            conn.send_all(Buffer::from_vec(buf.as_slice()[..n].to_vec()))
                .await
                .unwrap();
        });
        let client = TcpStream::connect(addr).await.unwrap();
        client
            .send_all(Buffer::from_vec(b"syscall-probe".to_vec()))
            .await
            .unwrap();
        let (r, buf) = client.recv(Buffer::from_vec(vec![0u8; 256])).await;
        let n = r.unwrap() as usize;
        let tcp_ok = &buf.as_slice()[..n] == b"syscall-probe";
        server.await;

        // File round-trip on the ring.
        let path =
            std::env::temp_dir().join(format!("urt-syscall-probe-{}.bin", std::process::id()));
        let f = File::open_rw(&path).unwrap();
        let payload: Vec<u8> = (0..65536u32).map(|i| i as u8).collect();
        f.write_all_at(0, Buffer::from_vec(payload.clone()))
            .await
            .unwrap();
        f.sync_all().await.unwrap();
        let got = f
            .read_exact_at(0, Buffer::from_vec(vec![0u8; payload.len()]))
            .await
            .unwrap();
        let file_ok = got.as_slice() == &payload[..];
        f.close().await.unwrap();
        let _ = std::fs::remove_file(&path);

        tcp_ok && file_ok
    });
    if ok {
        eprintln!("probe: data path OK");
        ExitCode::SUCCESS
    } else {
        eprintln!("probe: data mismatch");
        ExitCode::FAILURE
    }
}
