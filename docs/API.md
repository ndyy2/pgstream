# PGStream API Reference (v0.3.0)

Semua native dideklarasikan di `pawn/include/pgstream.inc`. Versi plugin yang bisa dicek runtime: `PGSTREAM_VERSION` = `300`, string versi via `PG_Version`.

Format string umum (dipakai `PG_AsyncQuery` dan `PG_ExecutePrepared`):

| Kode | Arti | Argumen Pawn |
|---|---|---|
| `i` / `d` | integer 32-bit | `new` int |
| `f` | float | `Float:` |
| `s` | string | array char |
| `b` | boolean | `bool:` |
| `n` | NULL | (tidak ada argumen) |

Parameter query memakai placeholder PostgreSQL `$1, $2, ...` sesuai urutan kode format.

---

## PG_Version

```pawn
native PG_Version(dest[], size = sizeof(dest));
```

Mengisi `dest` dengan teks versi plugin (mis. `"PGStream 0.3.0"`) dan me-return kode versi integer (`300` untuk v0.3.0).

```pawn
new version[64];
new code = PG_Version(version, sizeof(version));
printf("PGStream %d ('%s')", code, version);
```

## PG_Connect

```pawn
native PG_Connect(const host[], const user[], const password[], const database[], port = 5432, const callback[] = "");
```

Koneksi dengan parameter individual (bentuk key-value). Perilaku TLS ditentukan oleh field `sslmode` di `pgstream.toml` (`[database]`, default `require`) — parameter TLS tidak bisa di-set per-panggilan:

- `sslmode=verify-ca` / `verify-full` — sertifikat diverifikasi (root store `webpki-roots` + hostname check).
- `sslmode=require` / `prefer` — terenkripsi **tanpa** verifikasi sertifikat (rawan MITM); plugin memlog warning sekali per koneksi. Produksi wajib `verify-full`.
- `sslmode=disable` — tanpa TLS.

Return connection handle (integer ≥ 1). Koneksi sebenarnya async; hasilnya dikirim ke `callback`. Auto-reconnect aktif untuk handle ini (bisa dimatikan via `database.reconnect_enabled`).

### Kontrak callback (multi-shot)

Callback signature: `forward <name>(connection, bool:success);`

Karena supervisor auto-reconnect menjaga handle, callback **dipanggil lebih dari sekali**:

- `success=1` — setiap kali koneksi (re)berhasil. Terjadi juga setelah reconnect otomatis; gunakan momen ini untuk re-sync state aplikasi (reload cache, set ulang state sesi, dll).
- `success=0` — **tepat 1× per outage**: connect gagal di awal, atau koneksi yang sudah hidup mati (socket EOF / keepalive gagal). Tidak dipanggil ulang untuk setiap percobaan retry selama outage yang sama. Baca alasan via `PG_GetError`.

`PG_Prepare`/`PG_Listen` yang sudah pernah sukses tidak perlu dipanggil lagi setelah reconnect — keduanya di-restore otomatis.

```pawn
forward OnDBConnect(connection, bool:success);
g_conn = PG_Connect("127.0.0.1", "postgres", "secret", "samp_db", 5432, "OnDBConnect");
```

## PG_ConnectUrl

```pawn
native PG_ConnectUrl(const url[], const callback[] = "");
```

Koneksi lewat PostgreSQL URL. Semua mode `sslmode` didukung:

- `sslmode=disable` — tanpa TLS.
- `sslmode=prefer` — terenkripsi, **tanpa verifikasi sertifikat** (perilaku sama dengan `require` di PGStream).
- `sslmode=require` — terenkripsi, **tanpa verifikasi sertifikat** (rawan MITM; lihat README bagian TLS / sslmode).
- `sslmode=verify-ca` / `sslmode=verify-full` — sertifikat diverifikasi (root store `webpki-roots` + hostname check). Produksi wajib `verify-full`.

Jika `sslmode=` tidak ada atau kosong di URL, nilai `database.sslmode` di `pgstream.toml` (default `require`) dipakai sebagai fallback. Nilai yang tidak dikenal → koneksi ditolak (fail-closed).

Gunakan placeholder, contoh:

```pawn
forward OnDBConnect(connection, bool:success);

public OnGameModeInit()
{
    g_conn = PG_ConnectUrl(
        "postgresql://user:password@host:5432/dbname?sslmode=require&channel_binding=require",
        "OnDBConnect"
    );
    return 1;
}
```

Catatan error: jika URL tidak bisa diparse, koneksi gagal dan error dapat dibaca di callback via `PG_GetError`.

Kontrak callback identik dengan `PG_Connect`: `success=1` setiap koneksi (re)berhasil (termasuk setelah reconnect otomatis), `success=0` tepat 1× per outage. Handle yang dikembalikan juga dijaga supervisor auto-reconnect.

## PG_Close

```pawn
native PG_Close(connection);
```

Tutup koneksi handle dan bebaskan resource terkait. Setelah close, `PG_IsConnected` return `false`.

`PG_Close` juga **menghentikan supervisor auto-reconnect** untuk handle tersebut: handle dihapus dari registry, sehingga supervisor tidak lagi mencoba connect ulang dan callback connect tidak dipanggil lagi untuk handle itu. Supervisor memeriksa handle yang hilang tiap detik saat idle; percobaan connect yang sedang berjalan diselesaikan lebih dulu sebelum supervisor berhenti.

## PG_IsConnected

```pawn
native bool:PG_IsConnected(connection);
```

Return `true` hanya bila koneksi benar-benar hidup.

- `false` saat handle sedang `Connecting` (auto-reconnect berjalan), `Failed` (outage dengan `database.reconnect_enabled = false`), `Disconnected`, atau handle sudah ditutup.
- Sejak v0.3.0 socket EOF/error langsung mengubah status, jadi `PG_IsConnected` tidak lagi melaporkan `Connected` untuk koneksi yang sudah tertutup.

Selama handle sedang reconnecting (status `Connecting`), native `PG_AsyncQuery`/`PG_ExecutePrepared`/`PG_Begin`/`PG_Commit`/`PG_Rollback`/`PG_Listen`/`PG_Prepare` pada handle tersebut **mengembalikan `0` tanpa memanggil callback**: client tidak ada di registry, jadi perintahnya tidak dieksekusi sama sekali. Gamemode yang menunggu callback akan diam selama outage (bisa menit) — tunda query hingga callback connect `success=1` terpanggil kembali. Tidak ada antrean query otomatis selama reconnect.

## PG_GetError

```pawn
native PG_GetError(connection, dest[], size = sizeof(dest));
```

Mengisi `dest` dengan pesan error terakhir untuk koneksi: alasan kegagalan connect, alasan outage terakhir (mis. socket EOF dari server/pooler), atau error server dari `PG_Prepare`. Dipanggil dari callback ketika `success=0`, atau query error.

Setelah koneksi (re)berhasil, pesan error dibersihkan — `PG_GetError` mengembalikan string kosong. Jadi selama outage, `PG_GetError` berisi alasan outage; begitu reconnect sukses, isinya kosong.

### Error umum

- **`Max connections reached (N)`** — `N` = `pool.max_size` di `pgstream.toml`. Terjadi saat jumlah koneksi aktif (`Connecting`/`Connected`) sudah mencapai batas; koneksi baru ditolak (callback koneksi terpanggil dengan `success=0`; error terbaca via `PG_GetError`). Catatan: `max_size` adalah batas koneksi hidup, bukan ukuran pool idle.
- **`Query timed out after Ns`** — `N` = `database.query_timeout_seconds`. Query melebihi timeout; callback query tetap terpanggil dengan `result` berisi error (teks error ada di `result.error` internal — belum ada native untuk membacanya; `PG_GetError` hanya menampilkan error level koneksi). Tetap panggil `PG_FreeResult(result)`.
- **`Connection lost`** — log server saat socket mati: `[PGStream] Connection lost (conn N): <alasan> — reconnecting in Ns`. `<alasan>` diisi ke `PG_GetError` selama outage (contoh: `connection closed by server` saat server/pooler menutup socket, atau teks error socket). Supervisor lalu connect ulang dengan backoff 1s → 2s → 4s → … → cap `reconnect_max_delay_seconds` (default 30s).
- **`reconnect disabled`** — akhir log `Connection lost` bila `database.reconnect_enabled = false`: tidak ada percobaan connect ulang, status handle menjadi `Failed` dan `PG_IsConnected` tetap `false`. `PG_GetError` tetap berisi alasan outage.
- **`Keepalive probe failed on conn N (x): <alasan>`** — log server saat probe keepalive `SELECT 1` gagal (interval `database.keepalive_interval_seconds`, timeout `database.query_timeout_seconds`, default 15). Penghitung kegagalan harus mencapai **2 kegagalan berturut-turut** (`probe_failures >= 2`) sebelum koneksi dianggap mati → log `Connection lost` → supervisor reconnect; kegagalan pertama saja tidak memicu reconnect, dan probe sukses mengembalikan penghitung ke 0. Probe yang di-skip karena client sedang digunakan query lain tidak menimbulkan error — percobaan berikutnya baru 1 interval keepalive lagi.
- Koneksi yang melebihi `database.connect_timeout_seconds` gagal; detailnya terbaca via `PG_GetError` di callback koneksi.

## PG_EscapeString

```pawn
native PG_EscapeString(connection, const src[], dest[], size = sizeof(dest));
```

Escape string untuk injeksi literal SQL yang aman. Wajib punya koneksi valid (escape mengikuti server encoding).

```pawn
new raw[] = "O'Connor\\Admin; DROP TABLE users;--";
new esc[128];
PG_EscapeString(g_conn, raw, esc, sizeof(esc));
```

## PG_AsyncQuery

```pawn
native PG_AsyncQuery(connection, const query[], const callback[] = "", const format[] = "", {Float, _}:...);
```

Eksekusi query async, hasil ke callback:

- Callback signature: `forward <name>(connection, result, extra);`

`extra` menerima nilai yang di-set saat invoke pertama; untuk query varargs sederhana pass `""`. Query bisa parameterized lewat `$1, $2, ...` plus format varargs.

Satu statement per panggilan: string yang berisi beberapa statement (mis. `"INSERT ...; UPDATE ..."`) berbalik error dan tidak dieksekusi.

```pawn
forward OnTestQuery(connection, result, extra);
PG_AsyncQuery(g_conn, "SELECT 1+1 AS result", "OnTestQuery");

// Parameterized
forward OnTxInsert(connection, result, extra);
PG_AsyncQuery(g_conn,
    "INSERT INTO pgstream_test (name, score, active) VALUES ($1, $2, $3) RETURNING id, name, score",
    "OnTxInsert", "sib", "TestPlayer", 1337, 1
);
```

Catatan error: kalau query gagal SQL-nya, callback tetap terpanggil dengan `result` yang berisi error — teks error ada di `result.error` (internal); `PG_GetError` tidak menampilkan error level query. Selalu panggil `PG_FreeResult(result)` setelah selesai membaca.

## PG_Begin / PG_Commit / PG_Rollback

```pawn
native PG_Begin(connection, const callback[] = "");
native PG_Commit(connection, const callback[] = "");
native PG_Rollback(connection, const callback[] = "");
```

Transaksi async. Callback signature untuk ketiganya:

- `forward <name>(connection, bool:success);`

Gunakan pola: `Begin` → query-2 di tengah → `Commit` (atau `Rollback` saat gagal).

```pawn
forward OnTxBegin(connection, bool:success);
PG_Begin(g_conn, "OnTxBegin");
```

Sukses `Begin` ditandai `success=true` lalu query berikutnya masuk scope transaksi yang sama sampai `Commit`.

## PG_Listen

```pawn
native PG_Listen(connection, const channel[], const callback[] = "");
```

Subscribe ke channel PostgreSQL notify. Notifikasi yang masuk di-dispatch global ke:

- `forward OnPGNotify(connection, const channel[], const payload[]);`

Callback opsional (listened sukses/gagal):

- `forward <name>(connection, bool:success);`

Setelah reconnect, channel ini **di-issue ulang otomatis** oleh supervisor (`LISTEN <channel>`) — gamemode tidak perlu memanggil `PG_Listen` lagi. Kegagalan re-LISTEN hanya di-log server. Callback connect `success=1` tetap dipanggil setelah reconnect agak gamemode bisa re-sync hal lain.

```pawn
forward OnListenReady(connection, bool:success);
PG_Listen(g_conn, "pgstream_events", "OnListenReady");

public OnPGNotify(connection, const channel[], const payload[])
{
    printf("NOTIFY conn=%d channel='%s' payload='%s'", connection, channel, payload);
}
```

## PG_Notify

```pawn
native PG_Notify(connection, const channel[], const payload[] = "");
```

Kirim `NOTIFY channel, 'payload'` ke server. Penerima lain (termasuk sendiri di LISTEN yang sama) menerima lewat `OnPGNotify`.

## PG_Prepare

```pawn
native PG_Prepare(connection, const stmt_name[], const query[], const callback[] = "");
```

Simpan prepared statement dengan nama tantangan. Callback signature:

- `forward <name>(connection, bool:success);`

Pada gagal, `PG_GetError` memuat server error prepared statement.

Setelah reconnect, statement ini **di-prepare ulang otomatis** oleh supervisor (SQL disimpan per nama statement) — gamemode tidak perlu memanggil `PG_Prepare` lagi. Kalau re-prepare gagal (mis. tabel yang di-query sudah tidak ada), kegagalannya hanya di-log server dan statement tersebut tidak tersedia untuk `PG_ExecutePrepared` sampai gamemode mempersiapkannya ulang.

```pawn
forward OnPrepared(connection, bool:success);
PG_Prepare(g_conn, "get_player", "SELECT id, name, score FROM pgstream_test WHERE score > $1 ORDER BY score DESC", "OnPrepared");
```

## PG_ExecutePrepared

```pawn
native PG_ExecutePrepared(connection, const stmt_name[], const callback[] = "", const format[] = "", {Float, _}:...);
```

Eksekusi prepared statement yang sudah di-`PG_Prepare`. Format varargs sama dengan `PG_AsyncQuery`. Callback signature:

- `forward <name>(connection, result, extra);` (sama dengan `OnQueryComplete`)

```pawn
forward OnPreparedQuery(connection, result, extra);
PG_ExecutePrepared(g_conn, "get_player", "OnPreparedQuery", "i", 100);
```

## Result API — by index

```pawn
native PG_NumRows(result);
native PG_NumFields(result);
native PG_GetAffectedRows(result);
native PG_GetString(result, row, col, dest[], size = sizeof(dest));
native PG_GetInt(result, row, col);
native Float:PG_GetFloat(result, row, col);
native bool:PG_IsNull(result, row, col);
native PG_FieldName(result, col, dest[], size = sizeof(dest));
```

- `row` 0-based; hasil kosong (`NumRows == 0`) tidak boleh diakses.
- `PG_GetAffectedRows` non-zero untuk DML (`INSERT/UPDATE/DELETE`); DDL umumnya 0.
- `PG_FieldName` mengambil nama kolom per index.
- Untuk `TIMESTAMP`, baca sebagai string (`PG_GetString`).

## Result API — by name

```pawn
native PG_GetStringByName(result, row, const col_name[], dest[], size = sizeof(dest));
native PG_GetIntByName(result, row, const col_name[]);
native Float:PG_GetFloatByName(result, row, const col_name[]);
native bool:PG_IsNullByName(result, row, const col_name[]);
```

Sama dengan versi index, tapi kolom disebut nama. Nama harus persis sama dengan alias/label kolom di query (pakai `AS` bila perlu).

```pawn
new name[32];
new score = PG_GetIntByName(result, 0, "score");
PG_GetStringByName(result, 0, "name", name, sizeof(name));
```

## PG_FreeResult

```pawn
native PG_FreeResult(result);
```

Wajib dipanggil setelah pemakaian result selesai, baik di callback sukses maupun gagal — result tidak di-free otomatis.
