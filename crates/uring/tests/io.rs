// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Integration tests that exercise the real io_uring data path: a loopback TCP
//! echo, positional file I/O with fsync/fallocate, and ring timers.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use uring::{Buffer, File, Runtime, TcpListener, TcpStream, UdpSocket, sleep, spawn, timeout};

#[test]
fn tcp_loopback_echo() {
    let rt = Runtime::with_defaults().unwrap();
    rt.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = listener.local_addr();

        // Server: accept one connection, echo one buffer back.
        let server = spawn(async move {
            let conn = listener.accept().await.unwrap();
            let (r, buf) = conn.recv(Buffer::from_vec(vec![0u8; 1024])).await;
            let n = r.unwrap() as usize;
            assert_eq!(&buf.as_slice()[..n], b"ping");
            let echoed = conn
                .send_all(Buffer::from_vec(buf.as_slice()[..n].to_vec()))
                .await
                .unwrap();
            echoed.len()
        });

        let client = TcpStream::connect(addr).await.unwrap();
        let _ = client
            .send_all(Buffer::from_vec(b"ping".to_vec()))
            .await
            .unwrap();
        let (r, buf) = client.recv(Buffer::from_vec(vec![0u8; 1024])).await;
        let n = r.unwrap() as usize;
        assert_eq!(&buf.as_slice()[..n], b"ping");
        assert_eq!(server.await, 4);
    });
}

#[test]
fn tcp_v6_loopback() {
    let rt = Runtime::with_defaults().unwrap();
    rt.block_on(async {
        let listener = TcpListener::bind("[::1]:0".parse().unwrap()).unwrap();
        let addr = listener.local_addr();
        assert!(addr.is_ipv6());
        let server = spawn(async move {
            let conn = listener.accept().await.unwrap();
            let (r, buf) = conn.recv(Buffer::from_vec(vec![0u8; 64])).await;
            r.unwrap();
            buf.as_slice().to_vec()
        });
        let client = TcpStream::connect(addr).await.unwrap();
        client
            .send_all(Buffer::from_vec(b"v6!".to_vec()))
            .await
            .unwrap();
        assert_eq!(server.await, b"v6!");
    });
}

#[test]
fn file_write_read_sync() {
    let rt = Runtime::with_defaults().unwrap();
    let dir = std::env::temp_dir().join(format!("urt-uring-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("data.bin");
    rt.block_on(async move {
        let f = File::open_rw(&path).unwrap();
        f.allocate(0, 4096).await.unwrap();
        let payload: Vec<u8> = (0..4096u32).map(|i| i as u8).collect();
        f.write_all_at(0, Buffer::from_vec(payload.clone()))
            .await
            .unwrap();
        f.sync_all().await.unwrap();
        let got = f
            .read_exact_at(0, Buffer::from_vec(vec![0u8; 4096]))
            .await
            .unwrap();
        assert_eq!(got.as_slice(), &payload[..]);
        // partial read at an offset
        let (r, mid) = f.read_at(100, Buffer::from_vec(vec![0u8; 8])).await;
        assert_eq!(r.unwrap(), 8);
        assert_eq!(mid.as_slice(), &payload[100..108]);
        f.close().await.unwrap();
    });
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn timer_sleep_elapses() {
    let rt = Runtime::with_defaults().unwrap();
    rt.block_on(async {
        let start = Instant::now();
        sleep(Duration::from_millis(120)).await;
        assert!(
            start.elapsed() >= Duration::from_millis(100),
            "slept {:?}",
            start.elapsed()
        );
    });
}

#[test]
fn timeout_fires_and_cancels() {
    let rt = Runtime::with_defaults().unwrap();
    rt.block_on(async {
        // The inner future never completes -> the timeout wins.
        let never = async {
            sleep(Duration::from_secs(60)).await;
            1
        };
        let r: Result<i32, _> = timeout(Duration::from_millis(80), never).await;
        assert!(r.is_err());
    });
}

#[test]
fn timeout_future_wins() {
    let rt = Runtime::with_defaults().unwrap();
    rt.block_on(async {
        let quick = async {
            sleep(Duration::from_millis(10)).await;
            7
        };
        let r = timeout(Duration::from_secs(5), quick).await;
        assert_eq!(r.unwrap(), 7);
    });
}

#[test]
fn many_connections_concurrently() {
    let rt = Runtime::with_defaults().unwrap();
    rt.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr: SocketAddr = listener.local_addr();
        let server = spawn(async move {
            let mut total = 0u64;
            for _ in 0..20 {
                let conn = listener.accept().await.unwrap();
                let (r, buf) = conn.recv(Buffer::from_vec(vec![0u8; 32])).await;
                let n = r.unwrap();
                total += u64::from(n);
                let _ = conn
                    .send_all(Buffer::from_vec(buf.into_vec()[..n as usize].to_vec()))
                    .await;
            }
            total
        });
        let clients: Vec<_> = (0..20)
            .map(|i| {
                spawn(async move {
                    let c = TcpStream::connect(addr).await.unwrap();
                    let msg = format!("m{i}");
                    c.send_all(Buffer::from_vec(msg.clone().into_bytes()))
                        .await
                        .unwrap();
                    let (r, buf) = c.recv(Buffer::from_vec(vec![0u8; 32])).await;
                    let n = r.unwrap() as usize;
                    assert_eq!(&buf.as_slice()[..n], msg.as_bytes());
                })
            })
            .collect();
        for c in clients {
            c.await;
        }
        assert!(server.await >= 20);
    });
}

// The core buffer-ownership safety property (ADR 0001): if an operation future
// is dropped while its buffer is in flight, the reactor keeps the buffer alive
// until the CQE arrives (cancelling the op), so the kernel never writes into
// freed memory. Here a `recv` that never receives data is cancelled by a
// timeout; the runtime must stay sound and reclaim the buffer.
#[test]
fn dropped_recv_buffer_is_retained_until_cqe() {
    let rt = Runtime::with_defaults().unwrap();
    rt.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = listener.local_addr();
        // Accept and then sit idle: the peer never sends, so our recv blocks.
        let server = spawn(async move {
            let conn = listener.accept().await.unwrap();
            // Hold the connection open a while without sending.
            sleep(Duration::from_millis(300)).await;
            drop(conn);
        });
        let client = TcpStream::connect(addr).await.unwrap();
        // recv will never complete; the timeout drops the recv future mid-flight.
        let buf = Buffer::from_vec(vec![0u8; 4096]);
        let r = timeout(Duration::from_millis(80), client.recv(buf)).await;
        assert!(r.is_err(), "recv should have timed out");
        // The runtime is still usable and the cancelled op's resources were
        // reclaimed as its (cancelled) CQE was reaped.
        sleep(Duration::from_millis(20)).await;
        server.await;
    });
    // Dropping the runtime drains any outstanding cancel CQEs without UB.
}

#[test]
fn many_dropped_ops_stay_sound() {
    let rt = Runtime::with_defaults().unwrap();
    rt.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = listener.local_addr();
        let _server = spawn(async move {
            let mut conns = Vec::new();
            for _ in 0..10 {
                conns.push(listener.accept().await.unwrap());
            }
            sleep(Duration::from_millis(400)).await;
        });
        // Open several connections and abandon a recv on each via a short timeout.
        for _ in 0..10 {
            let c = TcpStream::connect(addr).await.unwrap();
            let buf = Buffer::from_vec(vec![0u8; 8192]);
            let _ = timeout(Duration::from_millis(30), c.recv(buf)).await;
            // `c` drops here too, closing through the ring.
        }
        sleep(Duration::from_millis(50)).await;
    });
}

#[test]
fn udp_unconnected_send_to_recv_from() {
    let rt = Runtime::with_defaults().unwrap();
    rt.block_on(async {
        let a = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let b = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let (r, _) = a
            .send_to(Buffer::from_vec(b"ping".to_vec()), b.local_addr())
            .await;
        assert_eq!(r.unwrap(), 4);
        let (r, buf, from) = b.recv_from(Buffer::from_vec(vec![0u8; 64])).await;
        assert_eq!(r.unwrap(), 4);
        assert_eq!(buf.as_slice(), b"ping");
        assert_eq!(from, Some(a.local_addr()));
        // v6 too
        let c = UdpSocket::bind("[::1]:0".parse().unwrap()).unwrap();
        let d = UdpSocket::bind("[::1]:0".parse().unwrap()).unwrap();
        let (r, _) = c
            .send_to(Buffer::from_vec(b"pong6".to_vec()), d.local_addr())
            .await;
        assert_eq!(r.unwrap(), 5);
        let (r, buf, from) = d.recv_from(Buffer::from_vec(vec![0u8; 64])).await;
        assert_eq!(r.unwrap(), 5);
        assert_eq!(buf.as_slice(), b"pong6");
        assert_eq!(from, Some(c.local_addr()));
    });
}
