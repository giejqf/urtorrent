# Configuration

What a client built on this library can configure, compared with the
settings qBittorrent exposes and maps onto libtorrent. The dividing line
(AGENTS.md 10): a limit or decision the engine has to enforce itself, such
as connection caps, upload slots, rates or the active-torrent queue, is a
library knob. Policy that needs only the snapshots and the public
operations belongs to the frontend and stays out.

## Library knobs

`SessionBuilder` and `AddTorrent` set a knob at start; the `Session` method
in brackets changes it at runtime. A session knob without such a method is
fixed for the session's lifetime. Defaults are in the rustdoc of each
method.

| Area | Session | Per torrent |
|---|---|---|
| Listening | `listen_port`, `listen_v4`, `listen_v6` (+ `set_listen`); a family set to `None` is neither listened on nor dialled | |
| Identity | `profile`: `native` or `qbt_5_2_3_lt2_0_14` (+ `set_profile`) | |
| Connections | `max_connections` (+ `set_max_connections`), `max_peers_per_torrent` (+ `set_max_peers_per_torrent`) | `max_peers` (+ `set_max_peers`) |
| Upload slots | `unchoke_slots` (+ `set_unchoke_slots`) | `max_uploads` (+ `set_max_uploads`) |
| Rates | `upload_limit`, `download_limit` (+ `set_rate_limits`) | `upload_limit`, `download_limit` (+ `set_torrent_rate_limits`) |
| Queue | `active_limits`: `downloads`, `seeds`, `total`, `count_slow` (+ `set_active_limits`) | `auto_managed` (+ `set_auto_managed`), `force_resume`, `move_in_queue`, `set_queue_position`; `pause` leaves the queue and `resume` rejoins it; `TorrentStatus::slow` marks a running torrent the queue no longer counts |
| Lifecycle | `pause_all`, `resume_all` | `paused`, `hold_after_metadata` (+ `release`), `remove_torrent` / `remove_torrent_with_files` |
| Transports | `transports`: `TcpOnly`, `PreferTcp`, `PreferUtp`, `UtpOnly` (+ `set_transports`); `encryption`: `Disabled`, `Enabled`, `Forced` (+ `set_encryption`) | |
| Discovery | `pex` (+ `set_pex`), `lsd` (+ `set_lsd`), `dht` (+ `set_dht`), `dht_bootstrap_nodes`, `dht_read_only`, `dht_state`, `add_dht_node` | `add_peer`, `add_tracker` / `remove_tracker`, `add_web_seed` / `remove_web_seed`, `force_reannounce`, `force_reannounce_tracker`, `scrape` |
| Peers | `ban_ip` / `unban_ip` / `banned_ips`, `ban_ip_range` / `unban_ip_range` / `banned_ip_ranges` | |
| Storage | `max_open_files`, `disk_thread`, `max_checking`, `piece_extent_affinity` | `save_path`, `resume_dir`, `resume_data`, `preallocate`, `file_priorities` (+ `set_file_priorities`), `set_piece_priorities` / `piece_priorities`, `sequential` (+ `set_sequential`), `rename_file`, `move_storage`, `force_recheck`, `save_resume_data` |
| Engine | `hash_threads`, `recv_ring`, `zero_copy_send`, `max_concurrent_announces`, `root_certificate_pem` | |

`Session::settings()` returns the runtime-changeable values in force.

- `set_listen` binds the new sockets first; if that fails, nothing changes.
  Then trackers hear `stopped` on the old port and `started` on the new.
  TCP connections stay, uTP connections drop with their UDP sockets, the
  DHT node carries on over the new sockets, and peers of a family that was
  switched off are disconnected.
- `set_profile` gives every torrent a fresh announce identity (with the
  same `stopped` / `started` pair) and restarts the DHT node with its
  tables. Connections already handshaked keep the identity they were made
  with.
- `set_dht(false)` keeps the routing tables for the next `set_dht(true)`.

## Snapshots

The snapshots carry what frontend policy needs:

- `TorrentStatus`: rates, counters, `active_time` / `seeding_time`,
  `queue_position`, `auto_managed`, `max_peers` / `max_uploads`, the
  torrent's own rate limits, `piece_length`, `comment` / `created_by` /
  `creation_date`, `web_seed_urls`. `statuses()` stays cheap for long
  lists by leaving files and trackers empty; `status(id)`, `files(id)` and
  `trackers(id)` fill them.
- `pieces(id)`: state, availability and priority per piece, for a piece
  bar.
- `PeerInfo`: choke and interest in both directions, rates, transport,
  source.
- `SessionStats`: session-wide counters.

## Daemon persistence

A daemon restarts from three things:

1. `torrent_file(id)`: the `.torrent` as bytes, with the info dictionary
   byte-exact so the info-hash holds. It is available for magnets too, once
   their metadata has arrived.
2. The resume data: the engine's `resume_dir` files, or blobs from
   `resume_data(id)` passed back through `AddTorrent::resume_data`. Anything
   `AddTorrent` does not set explicitly is restored from it
   (`docs/resume.md` lists what it holds).
3. The daemon's own table of frontend-side state (save path, paused,
   categories, tags, ...).

`Session::dht_state()` persists the DHT, restored with
`SessionBuilder::dht_state`.

## Frontend responsibilities (deliberately not in the library)

- **Share limits**: pause or remove at a ratio or seeding time. qBittorrent
  does this above libtorrent too; `uploaded`, `downloaded` and
  `seeding_time` are in the status.
- **Scheduler / alternative rate limits**: call `set_rate_limits` on a
  timer.
- **Categories, tags, watch folders, RSS, auto-remove, run-on-completion,
  notifications.**
- **Resume-data autosave cadence**: the engine saves periodically while a
  torrent changes and on shutdown; for a fixed cadence call
  `save_resume_data`.
- **Interface names**: resolve them to addresses and pass `listen_v4` /
  `listen_v6`.
- **Port randomisation**: pick a port and pass `listen_port`.
- **IP filter files**: file formats are a non-goal (AGENTS.md 1); read the
  file and pass its ranges to `ban_ip_range`.
- **First and last piece first**: give those pieces priority 7 with
  `set_piece_priorities`, as qBittorrent does through libtorrent's
  `prioritize_pieces`.
- **Incomplete-file suffix** (`.!qB`): rename with `rename_file`, and back
  on `Event::FileCompleted`. qBittorrent does the renaming itself too.

## Not offered, on purpose or for now

| Setting (libtorrent / qBittorrent) | Status |
|---|---|
| `announce_to_all_trackers` / `announce_to_all_tiers` | fixed to qBittorrent's values: every tier, the first working tracker in each (Q31) |
| `choking_algorithm` / `seed_choking_algorithm` | one each: libtorrent's `fixed_slots` choker when leeching, `round_robin` when seeding |
| `allow_multiple_connections_per_ip` | off, like the oracle (Q25) |
| `anonymous_mode` | would change identity; profiles own that |
| `announce_ip` | empty in qBittorrent; not implemented (Q22) |
| `connection_speed` / half-open limit | engine constant: at most 10 dials in flight per torrent |
| peer / request / inactivity timeouts | libtorrent's defaults, as constants (L3) |
| `min_reconnect_time` | libtorrent's 60 s, as a constant; `add_peer` bypasses it |
| `seed_mode` / "skip hash check" on add | not offered: advertising unverified pieces would break rule 1. A lazy per-piece verify is the honest form and a candidate |
| content layout (subfolder / no subfolder) | no add-time switch; `rename_file` gives the same result per file |
| proxies, UPnP / NAT-PMP, share mode, super-seeding | non-goals or roadmap (AGENTS.md 1, 4) |
