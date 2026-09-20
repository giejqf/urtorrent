// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! `urt-client`: the library under test as a process the lab can run inside a
//! network namespace. It drives `urtorrent` from `#[tokio::main]` (the
//! supported integration path, AGENTS.md 5.6), writes a JSON status snapshot
//! to `--status` a few times a second, and takes commands from `--control`
//! (a file the harness writes: `shutdown`, `pause`, `resume`, `reannounce`,
//! `save-resume`). No signals are needed for a graceful stop.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    missing_docs
)]

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use urtorrent::{AddTorrent, Event, Profile, Session, TorrentState};

struct Args {
    torrent: PathBuf,
    save: PathBuf,
    resume: Option<PathBuf>,
    status: Option<PathBuf>,
    control: Option<PathBuf>,
    listen_port: u16,
    profile: String,
    v4: Option<std::net::Ipv4Addr>,
    v6: Option<std::net::Ipv6Addr>,
    no_v4: bool,
    no_v6: bool,
    exit_when_complete: bool,
    sequential: bool,
}

fn parse_args() -> Result<Args> {
    let mut a = Args {
        torrent: PathBuf::new(),
        save: PathBuf::new(),
        resume: None,
        status: None,
        control: None,
        listen_port: 6881,
        profile: "native".into(),
        v4: None,
        v6: None,
        no_v4: false,
        no_v6: false,
        exit_when_complete: false,
        sequential: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(k) = it.next() {
        let mut val = || it.next().with_context(|| format!("{k} needs a value"));
        match k.as_str() {
            "--torrent" => a.torrent = PathBuf::from(val()?),
            "--save" => a.save = PathBuf::from(val()?),
            "--resume" => a.resume = Some(PathBuf::from(val()?)),
            "--status" => a.status = Some(PathBuf::from(val()?)),
            "--control" => a.control = Some(PathBuf::from(val()?)),
            "--listen-port" => a.listen_port = val()?.parse()?,
            "--profile" => a.profile = val()?,
            "--v4" => a.v4 = Some(val()?.parse()?),
            "--v6" => a.v6 = Some(val()?.parse()?),
            "--no-v4" => a.no_v4 = true,
            "--no-v6" => a.no_v6 = true,
            "--exit-when-complete" => a.exit_when_complete = true,
            "--sequential" => a.sequential = true,
            other => bail!("unknown argument {other}"),
        }
    }
    if a.torrent.as_os_str().is_empty() || a.save.as_os_str().is_empty() {
        bail!(
            "usage: urt-client --torrent <file> --save <dir> [--resume <dir>] [--status <file>] [--control <file>] [--listen-port N] [--profile native|qbt] [--v4 ip|--no-v4] [--v6 ip|--no-v6] [--exit-when-complete] [--sequential]"
        );
    }
    Ok(a)
}

fn peer_json(p: &urtorrent::PeerInfo) -> serde_json::Value {
    serde_json::json!({
        "addr": p.addr.to_string(), "client": p.client, "incoming": p.incoming,
        "downloaded": p.downloaded, "uploaded": p.uploaded, "is_seed": p.is_seed,
        "peer_id": p.peer_id.map(|id| String::from_utf8_lossy(&id).into_owned()),
    })
}

fn write_status(path: &std::path::Path, value: &serde_json::Value) {
    let tmp = path.with_extension("json.tmp");
    if std::fs::write(&tmp, value.to_string()).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    testkit::init_tracing();
    let args = parse_args()?;
    let profile = Profile::by_name(&args.profile)
        .with_context(|| format!("unknown profile {}", args.profile))?;
    let mut builder = Session::builder()
        .listen_port(args.listen_port)
        .profile(profile);
    if args.no_v4 {
        builder = builder.listen_v4(None);
    } else if let Some(v4) = args.v4 {
        builder = builder.listen_v4(Some(v4));
    }
    if args.no_v6 {
        builder = builder.listen_v6(None);
    } else if let Some(v6) = args.v6 {
        builder = builder.listen_v6(Some(v6));
    }
    let session = builder.build().await.context("starting the engine")?;
    tracing::info!(port = session.listen_port(), "urt-client up");
    let mut events = session.events();
    let bytes = std::fs::read(&args.torrent).context("reading torrent")?;
    let mut add = AddTorrent::metainfo(bytes, &args.save).sequential(args.sequential);
    if let Some(r) = &args.resume {
        add = add.resume_dir(r);
    }
    let id = session.add_torrent(add).await.context("adding torrent")?;

    let mut event_log: Vec<String> = Vec::new();
    let mut peers_seen: std::collections::BTreeMap<String, serde_json::Value> =
        std::collections::BTreeMap::new();
    let mut finished_at: Option<std::time::Instant> = None;
    let mut last_cmd = String::new();
    loop {
        // Drain events without blocking.
        while let Some(ev) = events.try_recv() {
            let line = format!("{ev:?}");
            tracing::info!("{line}");
            if matches!(ev, Event::TorrentFinished { .. }) && finished_at.is_none() {
                finished_at = Some(std::time::Instant::now());
            }
            if let Event::PeerDisconnected { info, .. } = &ev {
                peers_seen.insert(info.addr.to_string(), peer_json(info));
            }
            event_log.push(line);
            if event_log.len() > 500 {
                event_log.remove(0);
            }
        }
        let st = session.status(id).await?;
        let peers = session.peers(id).await.unwrap_or_default();
        for p in &peers {
            if p.peer_id.is_some() {
                peers_seen.insert(p.addr.to_string(), peer_json(p));
            }
        }
        if let Some(p) = &args.status {
            let v = serde_json::json!({
                "state": format!("{:?}", st.state),
                "error": st.error,
                "pieces_have": st.pieces_have,
                "pieces_total": st.pieces_total,
                "total_size": st.total_size,
                "downloaded": st.downloaded,
                "uploaded": st.uploaded,
                "left": st.left,
                "corrupt": st.corrupt,
                "redundant": st.redundant,
                "download_rate": st.download_rate,
                "peers": st.peers,
                "seeds": st.seeds,
                "complete": st.complete,
                "listen_port": session.listen_port(),
                "trackers": st.trackers.iter().map(|t| serde_json::json!({
                    "url": t.url, "working": t.working, "fails": t.fails,
                    "last_error": t.last_error, "seeders": t.seeders, "leechers": t.leechers,
                })).collect::<Vec<_>>(),
                "peer_list": peers.iter().map(peer_json).collect::<Vec<_>>(),
                "peers_seen": peers_seen.values().cloned().collect::<Vec<_>>(),
                "events": event_log,
            });
            write_status(p, &v);
        }
        if let Some(c) = &args.control
            && let Ok(cmd) = std::fs::read_to_string(c)
        {
            let cmd = cmd.trim().to_string();
            if !cmd.is_empty() && cmd != last_cmd {
                last_cmd = cmd.clone();
                tracing::info!("control: {cmd}");
                match cmd.as_str() {
                    "shutdown" => break,
                    "pause" => session.pause(id).await?,
                    "resume" => session.resume(id).await?,
                    "reannounce" => session.force_reannounce(id).await?,
                    "save-resume" => session.save_resume_data(id).await?,
                    other => tracing::warn!("unknown control command {other}"),
                }
            }
        }
        if args.exit_when_complete
            && st.state == TorrentState::Seeding
            && finished_at.is_some_and(|t| t.elapsed() > Duration::from_secs(2))
        {
            break;
        }
        if st.state == TorrentState::Error {
            tracing::error!("torrent error: {:?}", st.error);
            session.shutdown().await?;
            bail!("torrent error: {:?}", st.error);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    tracing::info!("shutting down");
    session.shutdown().await?;
    if let Some(p) = &args.status {
        let mut v: serde_json::Value = std::fs::read_to_string(p)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or(serde_json::json!({}));
        v["exited"] = serde_json::Value::Bool(true);
        write_status(p, &v);
    }
    Ok(())
}
