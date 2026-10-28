#!/usr/bin/env sh
# Build pgstream.dll (Windows x86 32-bit) from Linux via MinGW cross-chain.
set -eu
cd "$(dirname "$0")/.."

export PATH="$HOME/.cargo/bin:/home/linuxbrew/.linuxbrew/bin:$PATH"

cargo build --target i686-pc-windows-gnu --release "$@"

DLL="target/i686-pc-windows-gnu/release/pgstream.dll"
if [ ! -f "$DLL" ]; then
	echo "BUILD FAIL: $DLL missing" >&2
	exit 1
fi

file "$DLL"
# PE32 (bukan PE32+) membuktikan arsitektur 32-bit.
case "$(file -b "$DLL")" in
	*PE32\ *|*" PE32 (MS Windows) "*|*" PE32"*)
		echo "OK: 32-bit DLL." ;;
	*)
		echo "BUILD VERIFY FAIL: DLL bukan PE32 (32-bit)." >&2
		exit 1 ;;
esac
