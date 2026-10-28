# CHANGELOG — PGStream

## [0.2.1] — 2026-10-28 (patch hardening)

Patch penguatan di atas 0.2.0. `PGSTREAM_VERSION` tetap `200` (konstanta native ke klien Pawn); `Cargo.toml` kini `0.2.1` (sinkron dengan tag rilis; `PG_Connect`/`VERSION_TEXT` tetap menampilkan "0.2.x").

### Ditambahkan

- **TLS pada jalur `PG_Connect` (key-value)** — jalur ini sebelumnya tanpa TLS sama sekali. String koneksi kini selalu menyertakan `sslmode` dari config (`database.sslmode`, default `require`) — `src/plugin.rs::pg_connect`.
- **Config baru `database.sslmode`** (`src/config.rs`) — default `require`; nilai didukung: `disable`, `prefer`, `require`, `verify-ca`, `verify-full`. `pgstream.toml` lama tanpa key ini tetap kompatibel (fallback `require`; teruji di `tests/connect_config_tests.rs::toml_without_sslmode_falls_back_to_require`).
- **CI** — `.github/workflows/ci.yml`: fmt check, clippy, `cargo test` (host), cross-build `pgstream.dll` (PE32 x86, `i686-pc-windows-gnu`), upload artifact.
- **Release otomatis** — `.github/workflows/release.yml`: push tag `v*` → GitHub release berisi `pgstream.dll` + `pawn/include/pgstream.inc`; release notes diambil dari section teratas `CHANGELOG.md`.
- **E2E harness** — `scripts/test-e2e.sh <server-dir> [timeout-detik]`: build DLL, salin ke server SA:MP (wine), kompilasi `pawn/tests/pgstream_test.pwn` via `pawncc.exe` (wine), jalankan server, asersi log. URL database dari env `PGSTREAM_TEST_URL` (sekret tidak masuk repo); skip (exit 0) jika env kosong.
- **8 test baru** — `tests/connect_config_tests.rs`: resolusi sslmode bentuk key-value & URL, fallback saat `sslmode` kosong/tidak ada, nilai unknown fail-closed, default config, TOML lama tanpa `sslmode`, penolakan saat batas koneksi tercapai, regression `sslmode` ganda (last-wins + rewrite semua kemunculan).

### Diperbaiki

- **`sslmode` ganda tidak lagi memecah keputusan TLS** — `resolve_ssl_mode` (`src/config.rs`) kini memakai kemunculan **terakhir** (aturan yang sama dengan `tokio_postgres::Config::from_str`) dan menulis ulang **semua** kemunculan. Sebelumnya kemunculan pertama dibaca plugin sedangkan tokio-postgres membaca yang terakhir: URL `?sslmode=verify-full&sslmode=disable` membuat plugin memilih connector terverifikasi, sementara wire berjalan plaintext. Regression test: `tests/connect_config_tests.rs::duplicate_sslmode_last_wins_and_all_occurrences_rewritten`.
- **`cargo fmt --check` bersih** — formatting source + test diseragamkan (CI sebelumnya merah karena fmt check).

### Perilaku berubah

- **`query_timeout_seconds` & `connect_timeout_seconds` kini benar-benar diterapkan** — sebelumnya hanya didefinisikan. Query dibungkus `tokio::time::timeout` (`src/plugin.rs::execute_query_internal`, error `Query timed out after Ns`); koneksi pakai `Config::connect_timeout` (`spawn_connect`).
- **`pool.max_size` kini batas koneksi aktif** — `try_register_connection` menghitung handle berstatus `Connecting`/`Connected`; bila ≥ `max_size`, koneksi ditolak dengan error `Max connections reached (N)` (handle tetap disimpan berstatus `Failed` agar `PG_GetError` melaporkan alasannya). Sebelumnya angka ini tidak pernah menjadi batas apa pun.
- **Mode terenkripsi-tanpa-verifikasi (`require`/`prefer`) memunculkan warning** — satu kali per koneksi: `[PGStream] WARN: TLS tanpa verifikasi sertifikat (sslmode=...)`. Verifikasi penuh (`verify-ca`/`verify-full`) memakai connector `make_tls_connector_verified` (root store `webpki-roots` + hostname check).

## [0.2.0] — 2026

Menurut `pawn/include/pgstream.inc` (PGSTREAM_VERSION = 200), `src/plugin.rs` (VERSION_TEXT "PGStream 0.2.0"), dan riwayat `src/`.

### Ditambahkan

- **TLS/SSL** pada connect: mode `sslmode=require`, `verify-ca`, `verify-full`
  - `verify-full`/`verify-ca` memakai root store terverifikasi (`webpki-roots`) — `src/plugin.rs::make_tls_connector_verified`
  - `require` (dan sslmode kosong) memakai no-validate verifier = encrypted nbytes tapi tanpa autentikasi (unauthenticated encryption, setara `sslmode=require` di libpq); by design, dokumentasi menyarankan `verify-full` untuk produksi
- **Koneksi via URL** — `PG_ConnectUrl(url, callback)`; TLS otomatis aktif jika `sslmode=` ada di URL
- **Transaksi** — `PG_Begin`, `PG_Commit`, `PG_Rollback` dengan callback `(connection, bool:success)`
- **LISTEN/NOTIFY** — `PG_Listen`, `PG_Notify`; notifikasi dispatch ke callback global `OnPGNotify(connection, channel, payload)`
- **Prepared statements** — `PG_Prepare`, `PG_ExecutePrepared`
- **Parameterized query varargs** — `PG_AsyncQuery(..., format, ...)` dengan kode `'i'/'d'` (int), `'f'` (float), `'s'` (string), `'b'` (bool), `'n'` (NULL), placeholder `$1..$n`
- **Timestamp extraction** — ekstraksi tipe timestamp via `chrono` (kolom `tokio-postgres` `with-chrono-0_4`)
- **Config plugin** `pgstream.toml` (`src/config.rs`): `[database]` (host/port/database/username/password, `password_env`, connect/query timeout), `[pool].max_size`, `[logging].level`

### Bugfix

- **AMX PushString slot 31** — panggilan PushString di table AMX SDK harus dilakukan via index 31; selain itu crash
- **Dereferensi varargs int** — pawncc 3.2.3664 (SA-MP) mengirim argumen `...` sebagai AMX address (by reference); format `'i'`/`'f'`/`'b'` kini di-dereference dengan benar, `'n'` = NULL
- **Bounds `native_arg` ke jumlah byte ABI varargs** — baca native varargs tidak lagi melebihi rentang argumen yang benar-benar dipush oleh Pawn

## [0.1.0] — M0 awal

- Plugin cdylib Rust → Windows x86 32-bit (`pgstream.dll`), cross-compile `i686-pc-windows-gnu` via `scripts/build-windows.sh`
- Koneksi individual (`PG_Connect`, tanpa TLS) dan tipe dasar `tokio-postgres`
- Async query (`PG_AsyncQuery`) di tokio runtime background, dispatch hasil ke Pawn lewat `ProcessTick()`
- Result API by index: `PG_NumRows`, `PG_NumFields`, `PG_GetAffectedRows`, `PG_GetString`, `PG_GetInt`, `PG_GetFloat`, `PG_IsNull`, `PG_FieldName`
- `PG_Close`, `PG_IsConnected`, `PG_GetError`, `PG_EscapeString`, `PG_FreeResult`
- Registry handle: `CONNECTIONS`, `RESULTS` (`src/handles.rs`)
