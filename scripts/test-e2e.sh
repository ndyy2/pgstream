#!/usr/bin/env sh
# pgstream e2e harness (POSIX sh)
#
# Usage: scripts/test-e2e.sh <server-dir> [timeout-detik]
#   server-dir      SA:MP server Windows dir (samp-server.exe + pawno/ + plugins/ + gamemodes/)
#   timeout-detik   Server run timeout seconds (default: 40)
#
# Environment:
#   PGSTREAM_TEST_URL  Postgres URL (with sslmode=...) used by the live test.
#                      Secrets NEVER land in the repo; injected via sed into the copied .pwn.
#
# Behavior:
#   1. Build pgstream.dll via cargo (i686-pc-windows-gnu --release).
#   2. Copy DLL into <server-dir>/plugins/pgstream.dll.
#   3. Copy pawn/tests/pgstream_test.pwn -> <server-dir>/gamemodes/pgstream_test.pwn,
#      replacing the placeholder URL `postgresql://user:password@host:5432/dbname?sslmode=require`
#      with $PGSTREAM_TEST_URL via sed (ampersand & escaped for sed replacement).
#      Assumption: repo's pawn/tests/pgstream_test.pwn contains that exact placeholder URL.
#   4. Compile .pwn -> .amx via wine pawncc.exe with -i <server-dir>/pawno/include and
#      -i <repo>/pawn/include, output <server-dir>/gamemodes/pgstream_test.amx.
#   5. Run `wine <server-dir>/samp-server.exe` with timeout (cwd = server-dir); capture log.
#   6. Assert log contains PASS: TLS connection established, PASS: Inserted,
#      PASS RECONNECT, === ALL INTEGRATION TESTS COMPLETED ===, and no FAIL;
#      else print log & exit non-zero.
#
# If PGSTREAM_TEST_URL is empty/unset -> print SKIP message and exit 0 (no DB creds in repo).
set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SERVER_DIR="${1:-}"
TIMEOUT="${2:-40}"

export PATH="$HOME/.cargo/bin:/home/linuxbrew/.linuxbrew/bin:$PATH"

die() { echo "e2e: $*" >&2; exit 1; }

usage() {
    echo "Usage: scripts/test-e2e.sh <server-dir> [timeout-detik]"
    echo "Example: scripts/test-e2e.sh /home/andy/lab/novalife project/samp037_svr_R2-2-1_win32 40"
}

# unix absolute path -> Windows path (winepath if present, else default Z: drive)
to_win() {
    if command -v winepath >/dev/null 2>&1; then
        winepath -w "$1"
    else
        printf 'Z:%s\n' "$(printf '%s' "$1" | sed -e 's|^/||' -e 's|/|\\|g')"
    fi
}

if [ "$SERVER_DIR" = "" ]; then
    usage >&2
    die "server-dir required"
fi
if [ ! -d "$SERVER_DIR" ]; then
    die "server-dir not found: $SERVER_DIR"
fi
if [ ! -f "$SERVER_DIR/samp-server.exe" ]; then
    die "server-dir missing samp-server.exe: $SERVER_DIR/samp-server.exe"
fi
if [ ! -f "$SERVER_DIR/pawno/pawncc.exe" ]; then
    die "server-dir missing pawno/pawncc.exe: $SERVER_DIR/pawno/pawncc.exe"
fi
if ! command -v cargo >/dev/null 2>&1; then
    die "cargo not found (install Rust; PATH must include $HOME/.cargo/bin)"
fi
if ! command -v wine >/dev/null 2>&1; then
    die "wine not found"
fi

PGSTREAM_TEST_URL="${PGSTREAM_TEST_URL:-}"
if [ "$PGSTREAM_TEST_URL" = "" ]; then
    echo "SKIP: PGSTREAM_TEST_URL not set"
    exit 0
fi

echo "e2e: building DLL -> target/i686-pc-windows-gnu/release/pgstream.dll"
cargo build --target i686-pc-windows-gnu --release

DLL="$REPO_ROOT/target/i686-pc-windows-gnu/release/pgstream.dll"
test -f "$DLL" || die "DLL not built: $DLL"

mkdir -p "$SERVER_DIR/plugins" "$SERVER_DIR/gamemodes"

PLUGIN_DLL="$SERVER_DIR/plugins/pgstream.dll"
cp "$DLL" "$PLUGIN_DLL"

PWN_SRC="$REPO_ROOT/pawn/tests/pgstream_test.pwn"
test -f "$PWN_SRC" || die "test .pwn missing: $PWN_SRC"

GAMEMODE_PWN="$SERVER_DIR/gamemodes/pgstream_test.pwn"
GAMEMODE_AMX="$SERVER_DIR/gamemodes/pgstream_test.amx"

cp "$PWN_SRC" "$GAMEMODE_PWN"

# Rewrite placeholder URL with the real test URL (secrets stay out of the repo).
# Escape backslash first, then & and | for sed replacement (& -> \& keeps a literal ampersand).
ESCAPED_URL="$(printf '%s' "$PGSTREAM_TEST_URL" | sed -e 's/\\/\\\\/g' -e 's/[&|]/\\&/g')"
sed "s|postgresql://user:password@host:5432/dbname?sslmode=require|${ESCAPED_URL}|g" \
    "$GAMEMODE_PWN" > "$GAMEMODE_PWN.tmp"
mv "$GAMEMODE_PWN.tmp" "$GAMEMODE_PWN"

PWN_W="$(to_win "$GAMEMODE_PWN")"
OUT_W="$(to_win "$GAMEMODE_AMX")"
INC1_W="$(to_win "$SERVER_DIR/pawno/include")"
INC2_W="$(to_win "$REPO_ROOT/pawn/include")"
PAWNCC_W="$(to_win "$SERVER_DIR/pawno/pawncc.exe")"

echo "e2e: compiling .pwn -> .amx via pawncc.exe"
wine "$PAWNCC_W" \
    "-i$INC1_W" \
    "-i$INC2_W" \
    "$PWN_W" \
    "-o$OUT_W" \
    -d3 >/dev/null 2>&1 || die "pawncc compile failed"
test -f "$GAMEMODE_AMX" || die "amx not produced: $GAMEMODE_AMX"

LOG="$(mktemp)"
trap 'rm -f "$LOG"' EXIT INT TERM

echo "e2e: running server for $TIMEOUT s"
(cd "$SERVER_DIR" && timeout "$TIMEOUT" wine "$SERVER_DIR/samp-server.exe") >"$LOG" 2>&1 || true

OK=1
grep -qF "PASS: TLS connection established" "$LOG" || OK=0
grep -qF "PASS: Inserted" "$LOG" || OK=0
grep -qF "PASS RECONNECT" "$LOG" || OK=0
grep -qF "=== ALL INTEGRATION TESTS COMPLETED ===" "$LOG" || OK=0
if grep -qF "FAIL" "$LOG"; then OK=0; fi

if [ "$OK" -eq 0 ]; then
    echo "e2e FAIL: test assertions not met" >&2
    echo "=== SERVER LOG ===" >&2
    cat "$LOG" >&2
    exit 1
fi

echo "e2e PASS"
