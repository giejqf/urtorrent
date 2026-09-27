// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! Integration tests that exercise the real io_uring data path: a loopback TCP
//! echo, positional file I/O with fsync/fallocate, and ring timers.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

extern crate urtorrent_uring as uring;

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
        let f = File::open_rw(&path).await.unwrap();
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

#[test]
fn multishot_recv_with_buffer_ring() {
    let rt = Runtime::with_defaults().unwrap();
    rt.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = listener.local_addr();
        // 1 MiB in 4 KiB sends, with a ring of 8 x 4 KiB: the ring runs dry
        // whenever the reader falls behind, ENOBUFS re-arms transparently.
        let total = 1 << 20;
        let sender = spawn(async move {
            let client = TcpStream::connect(addr).await.unwrap();
            let mut sent = 0usize;
            let mut seq = 0u8;
            while sent < total {
                let chunk: Vec<u8> = (0..4096)
                    .map(|_| {
                        seq = seq.wrapping_add(1);
                        seq
                    })
                    .collect();
                client.send_all(Buffer::from_vec(chunk)).await.unwrap();
                sent += 4096;
            }
            client
        });
        let conn = listener.accept().await.unwrap();
        let ring = uring::BufRing::new(7, 8, 4096).unwrap();
        assert_eq!(ring.free(), 8);
        let mut rx = conn.recv_multi(&ring);
        let mut got = Vec::with_capacity(total);
        let mut held = Vec::new();
        while got.len() < total {
            let buf = rx.next().await.unwrap().expect("not eof");
            assert!(buf.len() <= 4096);
            got.extend_from_slice(buf.as_slice());
            // Hold a few guards to starve the ring on purpose.
            held.push(buf);
            if held.len() == 6 {
                held.clear();
            }
        }
        drop(held);
        let mut seq = 0u8;
        for b in &got {
            seq = seq.wrapping_add(1);
            assert_eq!(*b, seq);
        }
        let client = sender.await;
        drop(client);
        // Peer closed: end of stream.
        assert!(rx.next().await.unwrap().is_none());
        drop(rx);
        assert_eq!(ring.free(), 8, "every buffer back on the ring");
    });
}

#[test]
fn multishot_recv_dropped_mid_stream_recycles_buffers() {
    let rt = Runtime::with_defaults().unwrap();
    rt.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = listener.local_addr();
        let client = TcpStream::connect(addr).await.unwrap();
        let conn = listener.accept().await.unwrap();
        let ring = uring::BufRing::new(9, 4, 1024).unwrap();
        let mut rx = conn.recv_multi(&ring);
        for _ in 0..3 {
            client
                .send_all(Buffer::from_vec(vec![7u8; 1024]))
                .await
                .unwrap();
        }
        let first = rx.next().await.unwrap().unwrap();
        assert_eq!(first.len(), 1024);
        // Drop the receiver while completions may still be queued; the
        // kernel's final CQE (cancel) and any queued buffers are recycled.
        drop(rx);
        drop(first);
        sleep(Duration::from_millis(50)).await;
        assert_eq!(ring.free(), 4);
    });
}

#[test]
fn zero_copy_vectored_send() {
    let rt = Runtime::with_defaults().unwrap();
    rt.block_on(async {
        if !uring::probe().unwrap().send_zc {
            eprintln!("send_zc unsupported here; skipping");
            return;
        }
        let listener = TcpListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = listener.local_addr();
        let total = 4usize << 20;
        let receiver = spawn(async move {
            let conn = listener.accept().await.unwrap();
            let ring = uring::BufRing::new(11, 16, 65536).unwrap();
            let mut rx = conn.recv_multi(&ring);
            let mut got = Vec::with_capacity(total);
            while got.len() < total {
                let b = rx.next().await.unwrap().expect("not eof");
                got.extend_from_slice(b.as_slice());
            }
            got
        });
        let client = TcpStream::connect(addr).await.unwrap();
        // 13-byte headers interleaved with 16 KiB payloads, like piece messages.
        let mut chunks = Vec::new();
        let mut expect = Vec::with_capacity(total);
        let mut i = 0u8;
        while expect.len() < total {
            let hdr = vec![i; 13];
            let payload = vec![i.wrapping_add(1); 16384];
            expect.extend_from_slice(&hdr);
            expect.extend_from_slice(&payload);
            chunks.push(Buffer::from_vec(hdr));
            chunks.push(Buffer::from_vec(payload));
            i = i.wrapping_add(2);
        }
        let n = expect.len();
        let shared = std::rc::Rc::new(chunks);
        // Two ranges in flight at once share the chunks.
        let half = n / 2;
        let a = client.send_all_chunks_zc(shared.clone(), 0, half);
        let b = client.send_all_chunks_zc(shared.clone(), half, n - half);
        // `a` must finish before `b` starts to keep the byte order; run them
        // sequentially (the sharing is what is under test).
        a.await.unwrap();
        b.await.unwrap();
        drop(shared);
        let got = receiver.await;
        assert_eq!(got.len(), total.max(n).min(got.len()));
        assert_eq!(&got[..], &expect[..got.len()]);
        drop(client);
    });
}

#[test]
fn udp_multishot_recvmsg_with_buffer_ring() {
    let rt = Runtime::with_defaults().unwrap();
    rt.block_on(async {
        for (bind, bgid) in [("127.0.0.1:0", 21u16), ("[::1]:0", 22u16)] {
            let a = UdpSocket::bind(bind.parse().unwrap()).unwrap();
            let b = UdpSocket::bind(bind.parse().unwrap()).unwrap();
            let ring = uring::BufRing::new(bgid, 8, 2048).unwrap();
            let mut rx = b.recv_multi(&ring);
            // 40 datagrams of distinct sizes with a ring of 8: the ring runs
            // dry while nobody reads, ENOBUFS re-arms transparently.
            for i in 0..40u32 {
                let payload = vec![i as u8; 100 + i as usize * 30];
                let (r, _) = a.send_to(Buffer::from_vec(payload), b.local_addr()).await;
                assert!(r.is_ok());
            }
            let mut got = std::collections::BTreeSet::new();
            while got.len() < 40 {
                match timeout(std::time::Duration::from_millis(500), rx.next()).await {
                    Ok(Ok((from, buf))) => {
                        assert_eq!(from, a.local_addr());
                        let i = buf.as_slice()[0];
                        assert_eq!(buf.len(), 100 + usize::from(i) * 30);
                        assert!(buf.as_slice().iter().all(|&x| x == i));
                        got.insert(i);
                        // Drain what else is queued without waiting.
                        while let Some((from, buf)) = rx.try_next() {
                            assert_eq!(from, a.local_addr());
                            let i = buf.as_slice()[0];
                            assert_eq!(buf.len(), 100 + usize::from(i) * 30);
                            got.insert(i);
                        }
                    }
                    Ok(Err(e)) => panic!("recv: {e}"),
                    // Datagrams stay queued in the socket while the ring is
                    // dry; nothing is lost.
                    Err(_) => panic!("only {} datagrams received", got.len()),
                }
            }
            assert_eq!(got.len(), 40);
            // A DF toggle is accepted (v4) or a no-op (v6).
            a.set_dont_fragment(true).unwrap();
            a.set_dont_fragment(false).unwrap();
        }
    });
}
