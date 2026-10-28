# CHANGELOG — PGStream

## [0.3.3] — 2026-10-28

### Ditambahkan

- **`QueryFinishedExtras` completion + `dispatch_callback_mixed`** — event completion untuk `PG_AsyncQuery`/`PG_QueryFormat` dengan argumen ekstra di luar (conn, result, extra); `dispatch_callback_mixed` push argumen string sebagai AMX heap string (dikumpulkan & dirilis setelah exec) serta argumen cell sebagai plain cell.
- Parser format: flags/width/precision sebelum konversi (`%.2f`, `%05d`) di-skip (precision tidak relevan untuk bound param); specifier `%e`/`%q` dianggap string (MySQL-plugin style escaped string).

### Perbaikan

- `cargo fmt --all` bersih (formatting terakhir).

## [0.3.2] — 2026-10-28

### Ditambahkan

- **`PG_QueryFormat`** — printf-style formatter khusus Pawn/SA:MP: specifier `%d`/`%i` (int), `%f` (float), `%s` (string), `%c` (karakter dari cell), `%x`/`%X` (hex string) di dalam query dikonversi menjadi placeholder `$1..$N` dan parameter binding typed (`SqlParam`) — **bukan interpolasi string**, jadi input berbahaya (`O'Reilly`, `'; DROP TABLE x;--`, unicode) tetap terikat sebagai nilai.
- `%%` di dalam query jadi `%` literal.
- 14 unit test baru di `tests/sqlformat_tests.rs` + fase e2e `PASS FORMAT-INSERT`/`PASS FORMAT-QUERY` (termasuk string ber-kutip dan payload `%`).

### Perilaku parser

- `%` di dalam **string literal SQL** (`'...'`, escape `''`), **identifier quoted** (`"..."`), dan **komentar** (`--`, `/* */`) tidak dikonversi — tetap utuh. Contoh: `LIKE '%x%'` aman.
- Specifier lain (`%q`, `%e`, `%g`, width/flags `%+.2d`, dst.) → error `unsupported format specifier`.
- Jumlah vararg ≠ jumlah specifier → error `format specifier count mismatch (expected N, got M)`; query tidak dijalankan, callback (bila ada) dipanggil dengan `success=0`.
- Versi: `PGSTREAM_VERSION` 301 → 302; `PG_Version()` → `"PGStream 0.3.2"`.

## [0.3.1] — 2026-10-28

### Diperbaiki

- **Callback saat reconnecting** — `PG_AsyncQuery`/`PG_ExecutePrepared`/`PG_Begin`/`PG_Commit`/`PG_Rollback`/`PG_Listen`/`PG_Prepare` yang dipanggil saat koneksi sedang reconnecting (`status=Connecting`) kini menembakkan callback `success=0` (bukan peluru diam) — gamemode mendeteksi downtime dan tidak menunggu callback yang tidak pernah datang. `PG_Notify` tetap return 0 tanpa callback (tidak punya callback).
- **Poison-safe mutex** — semua `CONNECTIONS`/`RESULTS` `.lock().unwrap()` diganti `.lock().unwrap_or_else(|e| e.into_inner())`: akses tetap berfungsi bila mutex poisoned (crash di thread lain sepanjang runtime gas), tidak lagi bisa crash host thread SA:MP.

### Versi

- `PGSTREAM_VERSION` 300 → 301; `VERSION_CODE` 301; `PG_Version()` → `"PGStream 0.3.1"`; `Cargo.toml` 0.3.1.

## [0.3.0] — 2026-10-28

Supervisor per handle: koneksi yang mati dideteksi (EOF socket / keepalive), lalu connect ulang dengan backoff eksponensial. Versi: `PGSTREAM_VERSION` = `300`, `VERSION_CODE` = `300`, `PG_Version()` → `"PGStream 0.3.0"`, `Cargo.toml` `0.3.0`.

### Ditambahkan

- **Auto-reconnect per handle** — tiap `PG_Connect`/`PG_ConnectUrl` menjalankan supervisor sendiri (`src/plugin.rs::supervise`): connect → pump notifikasi → socket mati → backoff eksponensial 1s → 2s → 4s → … → cap `reconnect_max_delay_seconds` (default 30s) → connect ulang. Backoff direset ke 1s setiap koneksi berhasil (`src/config.rs::next_backoff`).
- **Keepalive** — probe `SELECT 1` tiap `keepalive_interval_seconds` (default 60s, `0` = mati) dengan timeout `query_timeout_seconds` (default 15s, sama dengan timeout query); probe di-skip saat koneksi sedang dipakai query lain (percobaan berikutnya 1 interval lagi); koneksi dianggap mati setelah 2 kegagalan probe berturut-turut (`probe_failures >= 2`) — kegagalan pertama hanya di-log. Mendeteksi socket half-open (`src/plugin.rs::keepalive_probe`).
- **Restore session setelah reconnect** — prepared statement di-prepare ulang otomatis (SQL disimpan per nama, `PgConnection::prepared_sqls`) dan channel `LISTEN` di-issue ulang otomatis (`PgConnection::listen_channels`). Gamemode tidak perlu mengulang `PG_Prepare`/`PG_Listen`.
- **Config baru di `[database]`** — `reconnect_enabled` (default `true`), `reconnect_max_delay_seconds` (default `30`), `keepalive_interval_seconds` (default `60`, `0` = mati). `pgstream.toml` versi 0.2.x tanpa key ini tetap kompatibel (default dipakai).
- **Test reconnect** — 9 unit test di `tests/reconnect_tests.rs` (default config, accessor global, TOML lama, TOML dengan key baru, backoff dobel & cap, backoff tidak pernah di bawah 1 detik, batas nama channel `LISTEN` 63 byte, pelacakan prepared SQL + channel `LISTEN`, `PG_Close` menghentikan supervisor) + fase reconnect pada e2e (`pawn/tests/pgstream_test.pwn` → `PASS RECONNECT`, diasersi `scripts/test-e2e.sh`). Catatan CI: `cargo test` di GitHub Actions berjalan tanpa `PGSTREAM_TEST_URL` — test live `keepalive_probe_succeeds_on_live_db` dan e2e selalu skip di runner, live coverage hanya lokal.

### Diperbaiki

- **EOF socket tidak lagi menyisakan status `Connected` palsu** — pump notifikasi mendeteksi EOF/error socket, handle ditandai bukan `Connected`, sehingga `PG_IsConnected` mengembalikan `false` dan supervisor langsung mencoba connect ulang. Sebelumnya socket yang sudah tertutup (mis. pooler Neon menutup koneksi idle) masih dilaporkan `Connected`.
- **Double-execute statement dihapus** — `execute_query_internal` tidak lagi menjalankan ulang statement lewat `client.execute()` saat query error (risiko `double-INSERT`).

### Perilaku berubah

- **Callback connect menjadi multi-shot** — `success=true` dipanggil setiap koneksi (re)berhasil; `success=false` tepat 1× per outage (connect gagal di awal, atau koneksi yang sudah hidup mati), bukan per percobaan retry.
- **Multi-statement tidak didukung** — satu statement per panggilan; string multi-statement kini berbalik error dan tidak dieksekusi.
- **`PGSTREAM_VERSION` 200 → 300** — `PG_Version()` kini mengembalikan kode `300` dengan teks `"PGStream 0.3.0"`.

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
