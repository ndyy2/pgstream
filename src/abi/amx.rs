//! AMX / plugin ABI boundary.
//!
//! Transliterated from the official SA:MP plugin SDK (0.3.7):
//! `plugincommon.h`, `amxplugin.cpp`, `amx.h` (mirror: udan11/samp-plugin-sdk,
//! cross-checked against samp-incognito/samp-streamer-plugin).
//!
//! Key facts this module encodes:
//! - Plugin entry functions are `__stdcall` (PLUGIN_CALL) on Windows x86 and
//!   must be exported under undecorated C names (`Supports`, `Load`, ...).
//! - The server hands out a function table at `ppData[PLUGIN_DATA_AMX_EXPORTS]`
//!   with one pointer per amx_* function, ordered per PLUGIN_AMX_EXPORT.
//! - AMX table functions and Pawn natives are `__cdecl` (AMXAPI / AMX_NATIVE_CALL
//!   are empty on MSVC) -> `extern "C"` in Rust.
//! - `cell` is `int32_t` (PAWN_CELL_SIZE 32).

#![allow(dead_code)] // table entries taken into use per milestone (M2/M3)

use std::os::raw::{c_char, c_int};

/// Pawn cell, always 32-bit for SA:MP.
pub type Cell = i32;

/// Opaque AMX instance. Layout belongs to the server; we only pass it back.
#[repr(C)]
pub struct Amx {
    _private: [u8; 0],
}

// --- pawn amx.h error codes (subset we need) -------------------------------
pub const AMX_ERR_NONE: c_int = 0;
pub const AMX_ERR_NOTFOUND: c_int = 19;
pub const AMX_ERR_PARAMS: c_int = 22;
pub const AMX_ERR_NATIVE: c_int = 9;

// --- plugincommon.h ---------------------------------------------------------
pub const SAMP_PLUGIN_VERSION: u32 = 0x0200;
pub const SUPPORTS_AMX_NATIVES: u32 = 0x10000;
pub const SUPPORTS_PROCESS_TICK: u32 = 0x20000;

/// `void (*logprintf)(char* format, ...)`
pub type LogPrintfFn = unsafe extern "C" fn(*const c_char, ...);

/// PLUGIN_DATA (index into the `ppData` array handed to `Load`).
pub mod slot {
    /// `ppData[0x00]` -> `void*` logprintf
    pub const LOGPRINTF: usize = 0x00;
    /// `ppData[0x10]` -> `void*` AMX function table (see PLUGIN_AMX_EXPORT)
    pub const AMX_EXPORTS: usize = 0x10;

    /// Indexes into the AMX function table (PLUGIN_AMX_EXPORT).
    pub const EXEC: usize = 7;
    pub const FIND_PUBLIC: usize = 9;
    pub const GET_ADDR: usize = 13;
    pub const GET_STRING: usize = 17;
    pub const PUSH: usize = 29;
    pub const PUSH_ARRAY: usize = 30;
    pub const PUSH_STRING: usize = 31;
    pub const RAISE_ERROR: usize = 32;
    pub const REGISTER: usize = 33;
    pub const RELEASE: usize = 34;
    pub const SET_STRING: usize = 37;
    pub const STR_LEN: usize = 39;
}

// --- amx.h ------------------------------------------------------------------

/// `AMX_NATIVE_INFO`, packed in the SDK; two 4-byte fields, so #[repr(C)]
/// produces the identical 8-byte layout on x86.
#[repr(C)]
pub struct NativeInfo {
    pub name: *const c_char,
    pub func: Option<NativeFn>,
}

unsafe impl Sync for NativeInfo {}

/// `int (AMX_NATIVE_CALL *)(AMX *amx, cell *params)` — cdecl.
pub type NativeFn = unsafe extern "C" fn(*mut Amx, *mut Cell) -> Cell;

pub type AmxRegisterFn = unsafe extern "C" fn(*mut Amx, *const NativeInfo, c_int) -> c_int;
pub type AmxFindPublicFn = unsafe extern "C" fn(*mut Amx, *const c_char, *mut c_int) -> c_int;
pub type AmxExecFn = unsafe extern "C" fn(*mut Amx, *mut Cell, c_int) -> c_int;
pub type AmxGetAddrFn = unsafe extern "C" fn(*mut Amx, Cell, *mut *mut Cell) -> c_int;
pub type AmxPushFn = unsafe extern "C" fn(*mut Amx, Cell) -> c_int;
pub type AmxPushStringFn =
    unsafe extern "C" fn(*mut Amx, *mut Cell, *mut Cell, *const c_char, c_int, c_int) -> c_int;
pub type AmxReleaseFn = unsafe extern "C" fn(*mut Amx, Cell) -> c_int;
pub type AmxSetStringFn =
    unsafe extern "C" fn(*mut Cell, *const c_char, c_int, c_int, usize) -> c_int;
pub type AmxGetStringFn =
    unsafe extern "C" fn(*mut c_char, *const Cell, c_int, usize) -> c_int;
pub type AmxStrLenFn = unsafe extern "C" fn(*const Cell, *mut c_int) -> c_int;

/// Native function receives `params[0] = argcount` (cell-indexed: `*params`).
pub unsafe fn native_arg(params: *mut Cell, i: Cell) -> Option<Cell> {
    // params[0] is the ARGUMENT SIZE IN BYTES (n*4), not the arg count
    let count = *params / (std::mem::size_of::<Cell>() as i32);
    if i < 1 || i > count {
        None
    } else {
        Some(*params.offset(i as isize))
    }
}

/// Reads a Pawn string from an AMX address into a Rust String.
pub unsafe fn get_amx_string(
    amx_ptr: *mut Amx,
    param: Cell,
    get_addr: AmxGetAddrFn,
    str_len: AmxStrLenFn,
    get_string: AmxGetStringFn,
) -> Option<String> {
    let mut phys: *mut Cell = std::ptr::null_mut();
    if get_addr(amx_ptr, param, &mut phys) != AMX_ERR_NONE || phys.is_null() {
        return None;
    }
    let mut len: c_int = 0;
    if str_len(phys, &mut len) != AMX_ERR_NONE || len < 0 {
        return None;
    }
    let mut buf = vec![0u8; (len as usize) + 1];
    if get_string(buf.as_mut_ptr() as *mut c_char, phys, 0, buf.len()) != AMX_ERR_NONE {
        return None;
    }
    // Drop terminating zero
    buf.pop();
    String::from_utf8(buf).ok()
}
