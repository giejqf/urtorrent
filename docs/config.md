# Configuration coverage

What a client built on this library can configure, checked (2026-09-21,
0.7.0, revisited for the daemon in 0.8.0) against the settings qBittorrent
exposes and maps onto libtorrent. The
rule for what lives here: anything that needs engine state or timing to get
right (limits the choker, dialler and queue enforce; anything that must hold
between two of our own decisions) is a library knob. Policy that only needs
snapshots and the public operations is the frontend's, and stays out.

## Library knobs

| Area | Session (`SessionBuilder` / runtime) | Per torrent (`AddTorrent` / runtime) |
|---|---|---|
| Listening | `listen_port`, `listen_v4`, `listen_v6` (a family off = never dialled either; + `set_listen`) | |
| Identity | `profile` (`native`, `qbt_5_2_3_lt2_0_14`; + `set_profile`) | |
| Connections | `max_connections` (+ `set_max_connections`), `max_peers_per_torrent` (+ `set_max_peers_per_torrent`) | `max_peers` (+ `set_max_peers`) |
| Upload slots | `unchoke_slots` (+ `set_unchoke_slots`) | `max_uploads` (+ `set_max_uploads`) |
| Rates | `upload_limit`, `download_limit` (+ `set_rate_limits`) | `upload_limit`, `download_limit` (+ `set_torrent_rate_limits`) |
| Queue | `active_limits` (`downloads` / `seeds` / `total` / `count_slow`, + `set_active_limits`) | `auto_managed` (+ `set_auto_managed`, `force_resume`, `move_in_queue`, `set_queue_position`); `pause` leaves the queue, `resume` rejoins it; `TorrentStatus::slow` for a running torrent the queue no longer counts |
| Transports | `transports` (`TcpOnly` / `PreferTcp` / `PreferUtp` / `UtpOnly`, + `set_transports`), `encryption` (`Disabled` / `Enabled` / `Forced`, + `set_encryption`) | |
| Discovery | `pex` (+ `set_pex`), `lsd` (+ `set_lsd`), `dht` (+ `set_dht`), `dht_bootstrap_nodes`, `dht_read_only`, `dht_state` | `add_peer`, `add_tracker` / `remove_tracker`, `add_web_seed` / `remove_web_seed`, `force_reannounce`, `scrape` |
| Peers | `ban_ip` / `unban_ip` / `banned_ips`, `ban_ip_range` / `unban_ip_range` / `banned_ip_ranges` (session-wide) | |
| Storage | `max_open_files`, `disk_thread`, `max_checking`, `piece_extent_affinity` | `save_path`, `resume_dir`, `preallocate`, `file_priorities` (+ `set_file_priorities`), `set_piece_priorities`, `sequential` (+ `set_sequential`), `rename_file`, `move_storage`, `force_recheck`, `save_resume_data` |
| Engine | `hash_threads`, `recv_ring`, `zero_copy_send`, `max_concurrent_announces`, `root_certificate_pem` | `paused`, `hold_after_metadata` (+ `release`) |

`Session::settings()` returns the values in force. Everything a
preferences page exposes changes live; only the engine tuning row
(`hash_threads`, `recv_ring`, `zero_copy_send`, `disk_thread`, ...) is fixed
for a session's lifetime. `set_listen` binds the new sockets before touching
anything (a failure changes nothing), then trackers hear `stopped` on the
old port and `started` on the new; TCP connections stay, uTP connections
drop with their UDP sockets, the DHT node carries on over the new ones, and
peers of a family switched off are disconnected. `set_profile` gives every
torrent a fresh announce identity (with the same `stopped` / `started`
pair) and restarts the DHT node with its tables; connections already
handshaked keep the identity they were made with. `set_dht(false)` keeps
the tables for the next `set_dht(true)`.

Snapshots carry what the policies above need: `TorrentStatus` (rates,
counters, `active_time` / `seeding_time`, `queue_position`, `auto_managed`,
`max_peers` / `max_uploads`, the torrent's own rate limits, `piece_length`,
`comment` / `created_by` / `creation_date`, web seed URLs; files and
trackers in `status(id)` / `files(id)` / `trackers(id)` while `statuses()`
stays cheap for large lists), `pieces(id)` (state and availability per
piece, for a piece bar), `PeerInfo` (both choke and interest directions,
rates, transport, source), `SessionStats`.

## Daemon persistence

A daemon restarts from three things: `torrent_file(id)` (the `.torrent`
as bytes, info dictionary byte-exact so the info-hash holds; the daemon
stores it, also for magnets once their metadata arrived), the resume data
(either the engine's `resume_dir` files or blobs from `resume_data(id)`
passed back through `AddTorrent::resume_data`: have-set, unfinished
pieces, accounting, timestamps, trackers and web seeds as they stood, queue
standing, sequential / rate limits / connection and slot caps, renamed
files, last peers; everything `AddTorrent` did not say explicitly is
restored from it; `docs/resume.md`), and its own table of the
frontend-side state (save path, paused, categories, tags, ...).
`Session::dht_state()` persists the DHT.

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
- **IP filter files**: file formats are a non-goal (AGENTS.md 1); read the
  file and pass its ranges to `ban_ip_range`.
- **First and last piece first**: set those pieces to priority 7 with
  `set_piece_priorities` (qBittorrent does the same through libtorrent's
  `prioritize_pieces`).
- **Incomplete-file suffix** (`.!qB`): rename with `rename_file`, and back
  on `Event::FileCompleted` (qBittorrent does the renaming itself too).

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
| `seed_mode` / "skip hash check" on add | not offered: advertising unverified pieces would break rule 1; a lazy per-piece verify is the honest form and a candidate |
| content layout (subfolder / no subfolder) | `rename_file` covers the effect per file; no add-time switch |
| proxies, UPnP / NAT-PMP, share mode, super-seeding | non-goals or roadmap (AGENTS.md 1, 4) |
