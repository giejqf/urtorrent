# Configuration coverage

What a client built on this library can configure, checked (2026-09-21,
0.7.0) against the settings qBittorrent exposes and maps onto libtorrent. The
rule for what lives here: anything that needs engine state or timing to get
right (limits the choker, dialler and queue enforce; anything that must hold
between two of our own decisions) is a library knob. Policy that only needs
snapshots and the public operations is the frontend's, and stays out.

## Library knobs

| Area | Session (`SessionBuilder` / runtime) | Per torrent (`AddTorrent` / runtime) |
|---|---|---|
| Listening | `listen_port`, `listen_v4`, `listen_v6` (a family off = never dialled either) | |
| Identity | `profile` (`native`, `qbt_5_2_3_lt2_0_14`) | |
| Connections | `max_connections` (+ `set_max_connections`), `max_peers_per_torrent` (+ `set_max_peers_per_torrent`) | `max_peers` (+ `set_max_peers`) |
| Upload slots | `unchoke_slots` (+ `set_unchoke_slots`) | `max_uploads` (+ `set_max_uploads`) |
| Rates | `upload_limit`, `download_limit` (+ `set_rate_limits`) | `upload_limit`, `download_limit` (+ `set_torrent_rate_limits`) |
| Queue | `active_limits` (`downloads` / `seeds` / `total` / `count_slow`, + `set_active_limits`) | `auto_managed` (+ `set_auto_managed`, `force_resume`, `move_in_queue`); `pause` leaves the queue, `resume` rejoins it |
| Transports | `transports` (`TcpOnly` / `PreferTcp` / `PreferUtp` / `UtpOnly`), `encryption` (`Disabled` / `Enabled` / `Forced`) | |
| Discovery | `pex`, `lsd`, `dht`, `dht_bootstrap_nodes`, `dht_read_only`, `dht_state` | `add_peer`, `add_tracker` / `remove_tracker`, `force_reannounce`, `scrape` |
| Storage | `max_open_files`, `disk_thread`, `max_checking`, `piece_extent_affinity` | `save_path`, `resume_dir`, `preallocate`, `file_priorities` (+ `set_file_priorities`), `sequential` (+ `set_sequential`), `move_storage`, `force_recheck`, `save_resume_data` |
| Engine | `hash_threads`, `recv_ring`, `zero_copy_send`, `max_concurrent_announces`, `root_certificate_pem` | `paused` |

Snapshots carry what the policies above need: `TorrentStatus` (rates,
counters, `active_time` / `seeding_time`, `queue_position`, `auto_managed`,
`max_peers` / `max_uploads`, files, trackers), `PeerInfo` (both choke and
interest directions, rates, transport, source), `SessionStats`.

## Frontend responsibilities (deliberately not in the library)

- **Share limits**: pause or remove at a ratio / seeding time (qBittorrent
  does this above libtorrent too; `uploaded`, `downloaded`, `seeding_time`
  are in the status).
- **Scheduler / alternative rate limits**: call `set_rate_limits` on a
  timer.
- **Categories, tags, watch folders, RSS, auto-remove, run-on-completion,
  notifications.**
- **Resume-data autosave cadence**: the engine saves periodically while a
  torrent changes and on shutdown; a frontend wanting a fixed cadence calls
  `save_resume_data`.
- **Interface names**: resolve to addresses and pass `listen_v4` /
  `listen_v6`.
- **Port randomisation**: pick and pass `listen_port`.
- **IP filter files**: file formats are a non-goal (AGENTS.md 1); a
  programmatic block list is on the candidate list below.

## Not offered, on purpose or for now

| Setting (libtorrent / qBittorrent) | Status |
|---|---|
| `announce_to_all_trackers` / `announce_to_all_tiers` | fixed to qBittorrent's defaults (all tiers, first working tracker per tier), Q9 |
| `choking_algorithm` / `seed_choking_algorithm` | one algorithm each (rate-based leech, round-robin seed) |
| `allow_multiple_connections_per_ip` | off, like the oracle (Q25) |
| `anonymous_mode` | would change identity; profiles own that |
| `announce_ip` | empty in qBittorrent; not implemented (Q22) |
| `connection_speed` / half-open limit | engine constant (10) |
| peer / request / inactivity timeouts | libtorrent's defaults as constants (L3) |
| `min_reconnect_time` | libtorrent's 60 s; `add_peer` bypasses it |
| listen port change at runtime | rebuild the session (candidate) |
| piece priorities / first-and-last-piece first | candidate: `set_piece_priorities` |
| programmatic IP block list | candidate |
| proxies, UPnP / NAT-PMP, share mode, super-seeding | non-goals or roadmap (AGENTS.md 1, 4) |
