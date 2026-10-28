//! PGStream — native PostgreSQL plugin for SA:MP (Rust, Windows x86 cdylib).

pub mod abi;
pub mod config;
pub mod database;
pub mod handles;
pub mod plugin;
pub mod runtime;

/// Stub for MinGW SJLJ / DWARF-2 mismatch on 32-bit Windows targets.
#[no_mangle]
pub extern "C" fn _Unwind_Resume() -> ! {
    std::process::abort();
}
