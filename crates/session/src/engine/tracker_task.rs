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
        peer_id: t.peer_id,
        port: ctx.listen_port,
        uploaded: t.stats.uploaded,
        downloaded: t.stats.downloaded,
        left: t.left(),
        corrupt: t.stats.corrupt,
        redundant: t.stats.redundant,
        key: t.announce_key,
        event: job.event,
        tracker_id: job.tracker_id.clone(),
        // Q8: `supportcrypto=1` unless encryption is disabled.
        crypto_supported: ctx.cfg.encryption != crate::api::EncryptionMode::Disabled,
    }
}

/// Perform one announce and feed the result back into the torrent. Used both
/// by the scheduler loop and, with `stopped`, by `torrent::stop`.
pub async fn announce_once(ctx: &Rc<Ctx>, torrent: &Rc<RefCell<Torrent>>, job: AnnounceJob) {
    let (request, id) = {
        let t = torrent.borrow();
        (build_request(ctx, &t, &job), t.id)
    };
    // This job belongs to one listen endpoint (address family). An IP-literal
    // tracker of the other family can never be reached from it: disable that
    // endpoint silently, as the oracle does (no error, no retries).
    let v6 = ctx
        .families
        .endpoints()
        .get(job.endpoint)
        .copied()
        .unwrap_or(false);
    if let Ok(url) = Url::parse(&job.url)
        && let Some(ip) = url.host_ip()
        && ip.is_ipv6() != v6
    {
        torrent
            .borrow_mut()
            .announcer
            .disable_endpoint(job.tier, job.index, job.endpoint);
        return;
    }
    let family = http::Families::only(v6);
    let result: Result<AnnounceResponse, String> = async {
        let url = Url::parse(&job.url).map_err(|e| e.to_string())?;
        let profile = &ctx.cfg.profile;
        if url.scheme == "udp" {
            return announce_udp(ctx, &url, &request, v6).await;
        }
        let resp = http::get(&ctx.dns, &ctx.tls, family, &url, &|u| {
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
                endpoint = job.endpoint,
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

/// BEP 15 announce: resolve, pick an address our UDP sockets can reach, then
/// connect + announce through the demultiplexer.
async fn announce_udp(
    ctx: &Rc<Ctx>,
    url: &Url,
    request: &AnnounceRequest,
    v6: bool,
) -> Result<AnnounceResponse, String> {
    let addrs = ctx
        .dns
        .resolve(&url.host, url.effective_port())
        .await
        .map_err(|e| format!("resolve {}: {e}", url.host))?;
    let to = addrs
        .into_iter()
        .find(|a| a.ip().is_ipv6() == v6 && ctx.udp.supports(a.ip()))
        .ok_or_else(|| format!("no usable address for {}", url.host))?;
    let shape = &ctx.cfg.profile.http;
    let numwant = if request.event == tracker::AnnounceEvent::Stopped {
        shape.numwant_stopped
    } else {
        shape.numwant
    } as i32;
    let mut path = url.path.clone();
    if let Some(q) = &url.query
        && !q.is_empty()
    {
        path.push('?');
        path.push_str(q);
    }
    ctx.udp.announce(to, request, numwant, &path).await
}

/// Scrape every tracker of the torrent, sequentially (a handful of URLs).
pub async fn scrape_all(ctx: &Rc<Ctx>, torrent: &Rc<RefCell<Torrent>>) {
    let (urls, hash, id) = {
        let t = torrent.borrow();
        (t.announcer.urls(), t.info.info_hash, t.id)
    };
    for announce_url in urls {
        let Some(scrape_url) = tracker::scrape::scrape_url(&announce_url) else {
            continue;
        };
        let result: Result<(u32, u32, u32), String> = async {
            let url = Url::parse(&scrape_url).map_err(|e| e.to_string())?;
            if url.scheme == "udp" {
                let addrs = ctx
                    .dns
                    .resolve(&url.host, url.effective_port())
                    .await
                    .map_err(|e| format!("resolve {}: {e}", url.host))?;
                let to = addrs
                    .into_iter()
                    .find(|a| ctx.udp.supports(a.ip()))
                    .ok_or_else(|| format!("no usable address for {}", url.host))?;
                let entries = ctx.udp.scrape(to, &[hash]).await?;
                return entries
                    .first()
                    .copied()
                    .ok_or_else(|| "empty scrape reply".to_string());
            }
            let profile = &ctx.cfg.profile;
            let resp = http::get(&ctx.dns, &ctx.tls, ctx.families, &url, &|u| {
                tracker::scrape::http_request(u, &[hash], profile)
            })
            .await?;
            if !(200..300).contains(&resp.status) {
                return Err(tracker::Error::Status(resp.status).to_string());
            }
            let files = tracker::scrape::parse_response(&resp.body).map_err(|e| e.to_string())?;
            let e = files
                .get(&hash)
                .copied()
                .ok_or_else(|| "scrape reply lacks our hash".to_string())?;
            Ok((e.complete, e.downloaded, e.incomplete))
        }
        .await;
        match result {
            Ok((complete, downloaded, incomplete)) => {
                torrent.borrow_mut().announcer.record_scrape(
                    &announce_url,
                    complete,
                    incomplete,
                    downloaded,
                );
                ctx.emit(Event::ScrapeReply {
                    id,
                    url: scrape_url,
                    complete,
                    incomplete,
                    downloaded,
                });
            }
            Err(e) => {
                tracing::debug!(url = %scrape_url, "scrape failed: {e}");
                ctx.emit(Event::TrackerError {
                    id,
                    url: scrape_url,
                    error: e,
                });
            }
        }
    }
}
