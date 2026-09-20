// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 urtorrent contributors

//! The per-torrent tracker task: asks the sans-IO [`tracker::Announcer`] what
//! is due, performs those announces over HTTP (on the ring), feeds the results
//! back, and sleeps until the next due time or until something (completion,
//! a forced re-announce, stop) kicks it.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::{Duration, Instant};

use tracker::{AnnounceJob, AnnounceRequest, AnnounceResponse, Url};

use super::Ctx;
use super::http;
use super::local::{Either, select2};
use super::torrent::{self, Torrent};
use crate::api::Event;

/// Never sleep longer than this between polls (guards against clock surprises).
const MAX_SLEEP: Duration = Duration::from_secs(60);

pub async fn run(ctx: Rc<Ctx>, torrent: Rc<RefCell<Torrent>>) {
    let (closing, kick) = {
        let t = torrent.borrow();
        (t.closing.clone(), t.tracker_kick.clone())
    };
    loop {
        if closing.is_set() {
            break;
        }
        let now = Instant::now();
        let (jobs, next) = {
            let mut t = torrent.borrow_mut();
            if !t.is_running() {
                break;
            }
            let jobs = t.announcer.poll(now);
            t.announces_in_flight += jobs.len();
            (jobs, t.announcer.next_due(now))
        };
        for job in jobs {
            let ctx2 = ctx.clone();
            let t2 = torrent.clone();
            uring::spawn(async move {
                announce_once(&ctx2, &t2, job).await;
                let mut t = t2.borrow_mut();
                t.announces_in_flight = t.announces_in_flight.saturating_sub(1);
                t.tracker_kick.notify();
            });
        }
        let sleep_for = next
            .map(|d| d.saturating_duration_since(now))
            .unwrap_or(MAX_SLEEP)
            .min(MAX_SLEEP)
            .max(Duration::from_millis(50));
        match select2(
            uring::sleep(sleep_for),
            select2(kick.wait(), closing.wait()),
        )
        .await
        {
            Either::Left(()) | Either::Right(Either::Left(())) => {}
            Either::Right(Either::Right(())) => break,
        }
    }
}

fn build_request(ctx: &Ctx, t: &Torrent, job: &AnnounceJob) -> AnnounceRequest {
    AnnounceRequest {
        info_hash: t.info.info_hash,
        peer_id: ctx.peer_id,
        port: ctx.listen_port,
        uploaded: t.stats.uploaded,
        downloaded: t.stats.downloaded,
        left: t.left(),
        corrupt: t.stats.corrupt,
        redundant: t.stats.redundant,
        key: t.announce_key,
        event: job.event,
        tracker_id: job.tracker_id.clone(),
    }
}

/// Perform one announce and feed the result back into the torrent. Used both
/// by the scheduler loop and, with `stopped`, by `torrent::stop`.
pub async fn announce_once(ctx: &Rc<Ctx>, torrent: &Rc<RefCell<Torrent>>, job: AnnounceJob) {
    let (request, id) = {
        let t = torrent.borrow();
        (build_request(ctx, &t, &job), t.id)
    };
    let result: Result<AnnounceResponse, String> = async {
        let url = Url::parse(&job.url).map_err(|e| e.to_string())?;
        let profile = &ctx.cfg.profile;
        let resp = http::get(&ctx.dns, ctx.families, &url, &|u| {
            request.http_request(u, profile)
        })
        .await?;
        if !(200..300).contains(&resp.status) {
            return Err(tracker::Error::Status(resp.status).to_string());
        }
        AnnounceResponse::parse(&resp.body).map_err(|e| e.to_string())
    }
    .await;
    let now = Instant::now();
    match result {
        Ok(resp) => {
            let added = {
                let mut t = torrent.borrow_mut();
                t.announcer.on_success(&job, &resp, now);
                if let Some(w) = &resp.warning {
                    tracing::info!(url = %job.url, "tracker warning: {w}");
                }
                t.add_candidates(ctx, &resp.peers)
            };
            tracing::debug!(
                url = %job.url,
                event = ?job.event,
                peers = resp.peers.len(),
                new = added,
                interval = resp.interval,
                "announce ok"
            );
            ctx.emit(Event::TrackerReply {
                id,
                url: job.url.clone(),
                peers: resp.peers.len(),
            });
            if added > 0 {
                torrent::on_new_candidates(ctx, torrent);
            }
        }
        Err(e) => {
            tracing::debug!(url = %job.url, event = ?job.event, "announce failed: {e}");
            torrent
                .borrow_mut()
                .announcer
                .on_failure(&job, e.clone(), now);
            ctx.emit(Event::TrackerError {
                id,
                url: job.url.clone(),
                error: e,
            });
        }
    }
}
