# PGStream

Plugin PostgreSQL native untuk SA:MP, ditulis dalam Rust. **Versi 0.3.1** (auto-reconnect + keepalive; di atas 0.2.x hardening TLS, v0.1.0 awal M0).

- Target: Windows x86 32-bit (`cdylib`), output `pgstream.dll` (PE32).
- Koneksi via `tokio-postgres` + `rustls` — tanpa dependensi libpq.
- Runtime async tokio di background; dispatch hasil ke Pawn lewat `ProcessTick()`.
-pawncc yang dipakai: 3.2.3664 (pawncc SA-MP). Lihat [Catatan ABI varargs](#catatan-abi-varargs-pawncc-323664).

## Daftar Isi

1. [Fitur](#fitur)
2. [Native API](#native-api)
3. [Build](#build)
4. [Deploy ke server SA:MP](#deploy-ke-server-samp)
5. [Konfigurasi pgstream.toml](#konfigurasi-pgstreamtoml)
6. [Auto-reconnect & keepalive](#auto-reconnect--keepalive)
7. [Kompilasi Pawn](#kompilasi-pawn)
8. [Catatan ABI varargs (pawncc 3.2.3664)](#catatan-abi-varargs-pawncc-323664)
9. [Arsitektur](#arsitektur)
10. [Testing](#testing)
11. [CI & Release](#ci--release)
12. [Batasan yang diketahui](#batasan-yang-diketahui)
13. [Verified against](#verified-against)

## Fitur

- **Zero-dependency**: tidak butuh libpq; protokol PostgreSQL murni Rust (`tokio-postgres`, `rustls`).
- **Asynchronous**: query jalan di tokio runtime background; game loop tidak pernah blocking.
- **Auto-reconnect**: supervisor per handle mendeteksi socket mati (EOF, keepalive) lalu connect ulang dengan backoff eksponensial; prepared statement & `LISTEN` di-restore otomatis. Lihat [Auto-reconnect & keepalive](#auto-reconnect--keepalive).
- **Keepalive**: probe `SELECT 1` periodik mendeteksi koneksi half-open (mis. pooler menutup koneksi idle).
- **TLS/SSL** di kedua jalur koneksi: `PG_ConnectUrl` (parameter `sslmode=` di URL) dan `PG_Connect` (field `sslmode` di `pgstream.toml`, default `require`). Mode: `disable`, `prefer`, `require`, `verify-ca`, `verify-full`. Teruji dari `pawn/tests/pgstream_test.pwn` ke Neon managed Postgres. Lihat [TLS / sslmode](#tls--sslmode) — produksi wajib `verify-full`.
- **Transaksi**: `PG_Begin` / `PG_Commit` / `PG_Rollback`.
- **LISTEN/NOTIFY**: pub/sub antipoll — `PG_Listen` / `PG_Notify`, callback global `OnPGNotify`.
- **Prepared statements**: `PG_Prepare` / `PG_ExecutePrepared`.
- **Parameterized queries**: placeholder `$1, $2, ...` + format string `'is f b'` (tal, float, string, bool, null) via varargs.
- **Batas koneksi aktif** — `pool.max_size` membatasi jumlah koneksi hidup (`Connecting`/`Connected`), bukan pool idle; koneksi di atas batas ditolak dengan error `Max connections reached (N)`.
- **Result API** dua arah: index kolom dan nama kolom.

## Native API

Ringkasan; spesifikasi lengkap per native lihat [docs/API.md](docs/API.md).

| Native | Fungsi |
|---|---|
| `PG_Version(dest[], size)` | Kode & teks versi plugin |
| `PG_Connect(host,user,pass,db,port,cb)` | Koneksi key-value; TLS sesuai `sslmode` di `pgstream.toml` (default `require`); callback `cb` multi-shot (dipanggil lagi setiap reconnect) |
| `PG_ConnectUrl(url,cb)` | Koneksi via URL; TLS sesuai `sslmode=` di URL (fallback: config); callback `cb` multi-shot (dipanggil lagi setiap reconnect) |
| `PG_Close(conn)` | Tutup koneksi + hentikan supervisor auto-reconnect |
| `PG_IsConnected(conn)` | Status hidup koneksi (`false` saat reconnecting) |
| `PG_GetError(conn,dest,size)` | Pesan error terakhir |
| `PG_EscapeString(conn,src,dest,size)` | Escape string untuk SQL |
| `PG_AsyncQuery(conn,query,cb,format,...)` | Query async + parameter varargs |
| `PG_Begin/PG_Commit/PG_Rollback(conn,cb)` | Transaksi |
| `PG_Listen(conn,channel,cb)` / `PG_Notify(conn,channel,payload)` | Pub/sub |
| `PG_Prepare(conn,name,query,cb)` / `PG_ExecutePrepared(conn,name,cb,format,...)` | Prepared statement |
| `PG_NumRows/PG_NumFields/PG_GetAffectedRows(result)` | Info result |
| `PG_GetString/PG_GetInt/PG_GetFloat/PG_IsNull(result,row,col,...)` / `..._ByName` | Baca cell, by index atau nama kolom |
| `PG_FieldName(result,col,dest,size)` | Nama kolom |
| `PG_FreeResult(result)` | Bebaskan memori result |

Semua native dideklarasikan di `pawn/include/pgstream.inc` (`PGSTREAM_VERSION` = 300).

## Build

Cross-compile dari Linux ke Windows i686 (MinGW toolchain harus terinstal, target `rustup target add i686-pc-windows-gnu`):

```sh
./scripts/build-windows.sh
```

Output: `target/i686-pc-windows-gnu/release/pgstream.dll`. Script memverifikasi DLL adalah PE32 (32-bit) — build gagal kalau tidak.

Kalau mau build langsung dengan cargo:

```sh
cargo build --target i686-pc-windows-gnu --release
```

## Deploy ke server SA:MP

1. Salin `pgstream.dll` ke folder `plugins/` server SA:MP.
2. Di `server.cfg` tambahkan:
   ```
   plugins pgstream.dll
   ```
3. Letakkan `pgstream.toml` di folder root server SA:MP (selevel `server.cfg`). Contoh minimal:

   ```toml
   [database]
   host = "127.0.0.1"
   port = 5432
   database = "novalife_db"
   username = "postgres"
   password_env = "PGSTREAM_DB_PASSWORD"
   sslmode = "verify-full"
   connect_timeout_seconds = 5
   query_timeout_seconds = 10
   reconnect_enabled = true
   reconnect_max_delay_seconds = 30
   keepalive_interval_seconds = 60

   [pool]
   max_size = 10

   [logging]
   level = "debug"
   ```

   Field lengkap lihat bagian [Konfigurasi](#konfigurasi-pgstreamtoml). Contoh memakai `password_env` (password dari env var, bukan plaintext di file) dan `sslmode = "verify-full"` (wajib produksi); `pool.max_size` = batas koneksi aktif, bukan pool idle; tiga key terakhir mengatur auto-reconnect & keepalive.
4. Restart server. Plugin load saat `Load()` SA:MP SDK; versi tercetak lewat `logprintf`.

## Konfigurasi pgstream.toml

Struct sumber `src/config.rs`. Semua section punya default; field wajib dalam praktiknya: `host`, `port`, `database`, `username`.

`[database]`:

| Field | Tipe | Default | Keterangan |
|---|---|---|---|
| `host` | string | `127.0.0.1` | Host database |
| `port` | u16 | 5432 | Port PostgreSQL |
| `database` | string | `samp_db` | Nama database |
| `username` | string | `postgres` | User database |
| `password` | string | `""` | Password |
| `password_env` | string (ops.) | — | Nama env var; jika ada dan env var terbaca, menimpa `password` |
| `sslmode` | string | `require` | Mode TLS; lihat [TLS / sslmode](#tls--sslmode) |
| `connect_timeout_seconds` | u64 | 5 | Batas durasi koneksi (diterapkan) |
| `query_timeout_seconds` | u64 | 15 | Batas durasi query (diterapkan); melebihi → error `Query timed out after Ns` |
| `reconnect_enabled` | bool | `true` | Auto-reconnect setelah koneksi mati; `false` → outage final, status handle `Failed` |
| `reconnect_max_delay_seconds` | u64 | 30 | Cap backoff reconnect (mulai 1s, dobel: 1→2→4→…→30) |
| `keepalive_interval_seconds` | u64 | 60 | Interval probe `SELECT 1`; `0` = probe mati |

`[pool]`:

| Field | Default | Keterangan |
|---|---|---|
| `max_size` | 5 | Batas jumlah koneksi aktif (`Connecting`/`Connected`), bukan pool idle; koneksi di atas batas ditolak dengan error `Max connections reached (N)` |

### TLS / sslmode

Perilaku TLS per mode (berlaku di kedua jalur koneksi — `PG_Connect` via field `sslmode` di `pgstream.toml`, `PG_ConnectUrl` via parameter URL):

| Mode | TLS | Verifikasi sertifikat | Catatan |
|---|---|---|---|
| `disable` | tidak | — | Koneksi plaintext. Hanya untuk lokal/LAN tepercaya. |
| `prefer` | ya | tidak | Terenkripsi, **tanpa** verifikasi. Sama dengan `require` di PGStream. |
| `require` | ya | tidak | Terenkripsi **tanpa** verifikasi sertifikat. **Rawan MITM.** Default kalau config tidak punya key. |
| `verify-ca` | ya | ya (webpki-roots + hostname) | |
| `verify-full` | ya | ya (webpki-roots + hostname) | **Wajib untuk produksi.** |

> **Peringatan**: `require`/`prefer` mengenkripsi traffic tapi **tidak memverifikasi identitas server yang kamu hubungkan** — penyerang di jalur (MITM) bisa menyajikan sertifikat apa pun. By-design (`setara require` di libpq), tapi **produksi wajib `sslmode=verify-full`**. Saat mode terenkripsi-tanpa-verifikasi aktif, plugin mencetak warning sekali per koneksi: `[PGStream] WARN: TLS tanpa verifikasi sertifikat (sslmode=...)`.

Catatan implementasi: `verify-ca` dan `verify-full` memakai connector terverifikasi yang sama (root store `webpki-roots`, cek hostname; TLS 1.2/1.3). Code tidak membedakan keduanya. Nilai `sslmode` yang tidak dikenal dibiarkan (koneksi ditolak / fail-closed). `sslmode` kosong atau tidak ada → fallback ke `database.sslmode` (default `require`).

`[logging]`:

| Field | Default | Keterangan |
|---|---|---|
| `level` | `info` | `debug` untuk troubleshooting |

Catatan: kalau file tidak ada / TOML tidak valid, `Config::load_from_file` diam-diam fallback ke struct Default (jangan berharap error log dari konfigurasi).

## Auto-reconnect & keepalive

Sejak v0.3.0, setiap handle dari `PG_Connect`/`PG_ConnectUrl` diawasi supervisor sendiri (`src/plugin.rs::supervise`).

### Alur supervisor

1. Connect ke database (TLS sesuai `sslmode`).
2. Pump notifikasi berjalan di background — pesan `LISTEN`/`NOTIFY` diteruskan ke Pawn lewat `OnPGNotify`.
3. Socket dipantau: EOF/error dari socket (mis. pooler menutup koneksi idle) atau probe keepalive yang gagal → koneksi dianggap mati.
4. Status handle diubah menjadi `Connecting` (jadi `PG_IsConnected` = `false`), `prepared_statements` dihapus (objek `Statement` tidak bisa hidup pindah ke client baru), lalu connect ulang setelah backoff.
5. Connect berhasil → prepared statement & channel `LISTEN` di-restore otomatis (`restore_session`), lalu callback connect dipanggil dengan `success=true`.

Slot handle tetap dihitung terhadap `pool.max_size` selama reconnecting (status `Connecting` masih dihitung sebagai koneksi aktif).

### Backoff

- Mulai 1 detik, menggandakan tiap percobaan gagal: 1s → 2s → 4s → 8s → 16s → 30s (`src/config.rs::next_backoff`).
- Cap = `database.reconnect_max_delay_seconds` (default 30).
- Backoff direset ke 1 detik setiap kali connect berhasil.
- `database.reconnect_enabled = false` → setelah outage tidak ada percobaan ulang; status handle `Failed`, log: `[PGStream] Connection lost (conn N): <alasan> — reconnect disabled`.

### Keepalive

- Probe `SELECT 1` setiap `database.keepalive_interval_seconds` (default 60; `0` = probe mati). Timeout probe memakai `database.query_timeout_seconds` (default 15) — sama dengan timeout query biasa, bukan angka tetap.
- Probe **dilewati** kalau koneksi sedang dipakai query lain (client lock dipegang). Pengatur waktu slot probe tetap maju meskipun probe di-skip, sehingga percobaan berikutnya baru **1 interval keepalive lagi** — bukan 1 detik setelahnya.
- Probe gagal → **2 kegagalan berturut-turut** (`probe_failures >= 2`) baru dianggap koneksi mati (socket half-open terdeteksi) → supervisor reconnect. Kegagalan pertama hanya di-log (`[PGStream] Keepalive probe failed on conn N (1): <alasan>`); probe yang sukses mengembalikan penghitung kegagalan ke 0.

### Callback connect (multi-shot)

Callback yang diberikan ke `PG_Connect`/`PG_ConnectUrl` **bisa dipanggil lebih dari sekali**:

| Callback | Kapan dipanggil | Berapa kali |
|---|---|---|
| `success=true` | setiap koneksi (re)berhasil | 1× per koneksi |
| `success=false` | outage — connect gagal di awal, atau koneksi yang sudah hidup mati | tepat 1× per outage (bukan per retry) |

Pakai callback ini untuk re-sync state aplikasi setiap kali koneksi kembali hidup (mis. muat ulang cache dari database, atur ulang state sesi). `success=false` sekali per outage = momen yang tepat untuk memberi tahu pemain/log bahwa database sedang tidak tersedia.

### Restore session setelah reconnect

- **Prepared statement**: SQL disimpan per nama (`PgConnection::prepared_sqls`); setelah reconnect, masing-masing di-prepare ulang. Gamemode **tidak perlu** memanggil `PG_Prepare` lagi. Kalau re-prepare gagal (mis. tabel sudah di-drop), kegagalannya hanya di-log server dan statement tersebut tidak tersedia sampai gamemode mempersiapkannya ulang.
- **Channel `LISTEN`**: setiap channel yang pernah sukses di-issue ulang sebagai `LISTEN <channel>` (`PgConnection::listen_channels`). Gamemode **tidak perlu** memanggil `PG_Listen` lagi. Kegagalan re-LISTEN hanya di-log.

## Kompilasi Pawn

Include: `pawn/include/pgstream.inc`. Contoh pemakaian: `pawn/tests/pgstream_test.pwn`.

Dua opsi compiler:

```sh
# Wine (Linux)
wine pawno/pawncc pawn/tests/pgstream_test.pwn -i pawn/include -o gamemodes/pgstream_test.amx

# Native (Windows / pawncc SA-MP)
pawncc pgstream_test.pwn -i+/include -o gamemodes\pgstream_test
```

Gunakan pawncc **3.2.3664** (dirilis bersama SA-MP). Compiler Pawn alternatif (Pawn 4 / openmp) punya ABI varargs berbeda — lihat di bawah.

## Catatan ABI varargs (pawncc 3.2.3664)

pawncc 3.2.3664 (SA-MP) push argumen `...` variadic ke AMX sebagai **AMX address (by reference)**, bukan nilai langsung:

- format `'i'`/`'d'` (int) dan `'f'` (float) dan `'b'` (bool): file asam men-dereference alamat cell untuk ambil nilai.
- format `'n'` = null: tidak di-dereference (parameter NULL di query).
- format `'s'` (string): alamat string AMX, dibaca rentang hingga terminator.

Bugfix terkait (v0.2.0):

- PushString di AMX SDK table harus dipanggil lewat **slot 31** (`src/abi/amx.rs`: `PUSH_STRING = 31`). Salah slot menyebabkan crash.
- Argumen `native_arg` dibounds ke **jumlah byte ABI varargs** — lebih dari itu menambatkan data kotor.

Konsekuensi praktis untuk pemilik gamemode:

- Jangan panggil `PG_AsyncQuery`/`PG_ExecutePrepared` dari compiler selain pawncc 3.2.3664.
- Selalu isi `format` dan argumen secara berpasangan; format `'n'` tidak butuh argumen di daftar varargs.
- Ukuran array tujuan (`dest[]`) dihitung dengan `sizeof(dest)` agar tidak overread.

## Arsitektur

Plugin adalah cdylib (`crate-type = ["cdylib", "rlib"]`) yang diekspor melalui SDK SA:MP (`Supports`, `Load`, `Unload`, `ProcessTick`, amx_functions table). Di `Load()` plugin register semua native lewat AMX callback registration (tabel SDK index 80 dst, `PushString` = 31) dan menyimpan pointer ke `logprintf` untuk output server console.

Tiap koneksi (management oleh `handles.rs`: `CONNECTIONS`, `RESULTS`) menjalankan command di tokio runtime multi-thread background. Hasil (rows, error, event `LISTEN`, penyelesaian query/transaksi) dikembalikan sebagai event ke queue (`CompletionEvent`); `ProcessTick()` dari main thread SA:MP mem-fetch events tiap tick dan menjalankan publik Pawn callback (`OnQueryComplete(connection, result, extra)` dsb) — jadi tidak ada thread Pawn yang dieksekusi di luar main thread.

## Testing

- Unit/integration Rust: `cargo test`.
  - `tests/reconnect_tests.rs` — 9 test untuk auto-reconnect: default config, accessor global (`reconnect_enabled`/`reconnect_max_delay()`/`keepalive_interval()`), TOML lama tanpa key reconnect (kompatibilitas default), TOML dengan key baru, backoff (`next_backoff` dobel & cap), backoff tidak pernah di bawah 1 detik (`reconnect_max_delay_seconds = 0`), batas nama channel `LISTEN` 63 byte (NAMEDATALEN, dihitung per byte), pelacakan prepared SQL (`prepared_sqls`) dan channel `LISTEN` (`listen_channels`), dan `PG_Close` yang menghapus handle sehingga supervisor berhenti.
  - `src/plugin.rs::keepalive_probe_succeeds_on_live_db` — live test keepalive probe terhadap database; dilewati (SKIP) bila `PGSTREAM_TEST_URL` tidak di-set.
  - **CI tidak menjalankan test live**: runner GitHub Actions tidak punya `PGSTREAM_TEST_URL`, jadi `keepalive_probe_succeeds_on_live_db` selalu skip (hijau) dan harness e2e `scripts/test-e2e.sh` juga skip. Live coverage hanya bisa dijalankan lokal.
- Live test end-to-end: `pawn/tests/pgstream_test.pwn` — mencakup TLS connect, SELECT/INSERT, transaksi, prepared statement, LISTEN/NOTIFY, escape string, **dan fase reconnect** (self-terminate backend → socket EOF → plugin connect ulang pada handle yang sama; log `PASS RECONNECT`). Jalankan sebagai gamemode di server SA:MP dengan `pgstream.toml` mengarah ke database test.
- E2E harness: `scripts/test-e2e.sh <server-dir> [timeout-detik]` — build `pgstream.dll` (cross `i686-pc-windows-gnu`), salin ke `plugins/`, kompilasi `pawn/tests/pgstream_test.pwn` via wine `pawncc.exe`, jalankan server, asersi log (`PASS: TLS connection established`, `PASS: Inserted`, `PASS RECONNECT`, `=== ALL INTEGRATION TESTS COMPLETED ===`, tanpa `FAIL`). URL database test dari env **`PGSTREAM_TEST_URL`** (sekret tidak disimpan di repo; disuntikkan ke salinan `.pwn` via `sed`). Jika `PGSTREAM_TEST_URL` kosong/tidak di-set → print `SKIP` & exit 0.

## CI & Release

- **CI** (`.github/workflows/ci.yml`, jalan di setiap push/PR): `cargo fmt --check`, clippy, `cargo test` (host), cross-build `pgstream.dll` (`i686-pc-windows-gnu`, PE32 x86), upload artifact.
- **Release otomatis** (`.github/workflows/release.yml`): push tag `v*` → GitHub release berisi `pgstream.dll` + `pawn/include/pgstream.inc`; release notes diambil dari section teratas `CHANGELOG.md`. Tag ulang release yang sama meng-overwrite file (`--clobber`).

## Batasan yang diketahui

- **Multi-statement tidak didukung** — satu statement per panggilan `PG_AsyncQuery`/`PG_ExecutePrepared`; string yang berisi beberapa statement berbalik error dan tidak dieksekusi (sebagian maupun keseluruhan).
- **Transaksi yang sedang berjalan hilang saat reconnect** — transaksi terbuka hidup di sesi yang mati; server melakukan rollback. Setelah reconnect, gamemode harus mengeluarkan `PG_Begin` lagi (momen yang tepat: callback connect `success=true`).
- **Callback saat reconnect** — selama status `Connecting`, native `PG_AsyncQuery`/`PG_Begin`/`PG_Commit`/`PG_Rollback`/`PG_Listen`/`PG_Prepare`/`PG_ExecutePrepared` mengembalikan `0` tapi tetap memanggil callback dengan `success=0` (client tidak ada — perintah di-skip). Gamemode bisa memakai ini untuk menunda kerja hingga `OnDBConnect(success=1)` berikutnya. Detail: [docs/API.md](docs/API.md).
- **`PG_FreeResult` wajib dipanggil** — result tidak dibebaskan otomatis; setiap result yang masuk ke callback query harus di-free (sukses maupun gagal) supaya memori tidak menumpuk.
- **Timeout statement/queue tidak mencakup antre lock** — `query_timeout_seconds` hanya berlaku selama eksekusi query; waktu menunggu giliran lock koneksi (query lain masih jalan) tidak dihitung terhadap timeout.
- Tipe kolom belum didukung: `NUMERIC`, `UUID`, `JSON`/`JSONB`, `BYTEA`. Baca via `PG_GetString` tidak dijamin.
- **`sslmode=require`/`prefer` tidak memverifikasi sertifikat server** (encrypted tapi unauthenticated — setara `require` di libpq). Berlaku untuk kedua jalur koneksi (`PG_Connect` via config, `PG_ConnectUrl` via URL). By design; **produksi wajib `sslmode=verify-full`** (lihat [TLS / sslmode](#tls--sslmode)).
- Format varargs terikat ke **pawncc 3.2.3664**. Compiler Pawn lain tak kompatibel.
- `PG_EscapeString` pada koneksi yang belum connect (`conn=0`) didokumentasi di test bergantung pada koneksi pertama; holder harus punya koneksi valid.

## Verified against

| Komponen | Versi |
|---|---|
| SA:MP | 0.3.7-R2 |
| PostgreSQL | 18.6 (Neon) |
| pawncc | 3.2.3664 |
