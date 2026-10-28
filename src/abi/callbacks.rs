use std::collections::HashSet;
use std::ffi::CString;
use std::os::raw::c_int;
use std::sync::Mutex;
use once_cell::sync::Lazy;

use crate::abi::amx::{self, Amx, Cell};
use crate::plugin;

/// Active AMX instances loaded by the server (gamemode + filterscripts).
pub static AMX_INSTANCES: Lazy<Mutex<HashSet<usize>>> =
    Lazy::new(|| Mutex::new(HashSet::new()));

pub fn register_amx(amx_ptr: *mut Amx) {
    let mut set = AMX_INSTANCES.lock().unwrap();
    set.insert(amx_ptr as usize);
}

pub fn unregister_amx(amx_ptr: *mut Amx) {
    let mut set = AMX_INSTANCES.lock().unwrap();
    set.remove(&(amx_ptr as usize));
}

/// Dispatches a public callback to all loaded AMX scripts that export it.
/// Parameters are passed as `args` in declaration order (arg1, arg2, ...).
/// They are pushed to AMX in reverse order per Pawn cdecl convention.
pub fn dispatch_callback(name: &str, args: &[Cell]) {
    if name.is_empty() {
        return;
    }

    let Ok(c_name) = CString::new(name) else {
        return;
    };

    let find_public: Option<amx::AmxFindPublicFn> = unsafe { plugin::table_fn(amx::slot::FIND_PUBLIC) };
    let push_fn: Option<amx::AmxPushFn> = unsafe { plugin::table_fn(amx::slot::PUSH) };
    let exec_fn: Option<amx::AmxExecFn> = unsafe { plugin::table_fn(amx::slot::EXEC) };

    let (Some(find_public), Some(push_fn), Some(exec_fn)) = (find_public, push_fn, exec_fn) else {
        return;
    };

    let instances: Vec<usize> = {
        let set = AMX_INSTANCES.lock().unwrap();
        set.iter().copied().collect()
    };

    for amx_addr in instances {
        let amx_ptr = amx_addr as *mut Amx;
        let mut idx: c_int = 0;
        let err = unsafe { find_public(amx_ptr, c_name.as_ptr(), &mut idx) };
        if err == amx::AMX_ERR_NONE {
            // Push arguments in reverse order (right to left)
            for &val in args.iter().rev() {
                unsafe { push_fn(amx_ptr, val) };
            }
            let mut retval: Cell = 0;
            unsafe { exec_fn(amx_ptr, &mut retval, idx) };
        }
    }
}

/// Dispatches a notification event to Pawn callback `OnPGNotify(connection, const channel[], const payload[])`.
pub fn dispatch_notification(conn_id: Cell, channel: &str, payload: &str) {
    let Ok(c_name) = CString::new("OnPGNotify") else { return; };
    let Ok(c_chan) = CString::new(channel) else { return; };
    let Ok(c_payl) = CString::new(payload) else { return; };

    let find_public: Option<amx::AmxFindPublicFn> = unsafe { plugin::table_fn(amx::slot::FIND_PUBLIC) };
    let push_string: Option<amx::AmxPushStringFn> = unsafe { plugin::table_fn(amx::slot::PUSH_STRING) };
    let push_fn: Option<amx::AmxPushFn> = unsafe { plugin::table_fn(amx::slot::PUSH) };
    let exec_fn: Option<amx::AmxExecFn> = unsafe { plugin::table_fn(amx::slot::EXEC) };
    let release_fn: Option<amx::AmxReleaseFn> = unsafe { plugin::table_fn(amx::slot::RELEASE) };

    let (Some(find_public), Some(push_string), Some(push_fn), Some(exec_fn), Some(release_fn)) =
        (find_public, push_string, push_fn, exec_fn, release_fn)
    else {
        return;
    };

    let instances: Vec<usize> = {
        let set = AMX_INSTANCES.lock().unwrap();
        set.iter().copied().collect()
    };

    for amx_addr in instances {
        let amx_ptr = amx_addr as *mut Amx;
        let mut idx: c_int = 0;
        let err = unsafe { find_public(amx_ptr, c_name.as_ptr(), &mut idx) };
        if err == amx::AMX_ERR_NONE {
            let mut amx_addr_p: Cell = 0;
            let mut amx_addr_c: Cell = 0;
            unsafe {
                push_string(amx_ptr, &mut amx_addr_p, std::ptr::null_mut(), c_payl.as_ptr(), 0, 0);
                push_string(amx_ptr, &mut amx_addr_c, std::ptr::null_mut(), c_chan.as_ptr(), 0, 0);
                push_fn(amx_ptr, conn_id);
            }
            let mut retval: Cell = 0;
            unsafe { exec_fn(amx_ptr, &mut retval, idx) };
            unsafe {
                if amx_addr_c != 0 { release_fn(amx_ptr, amx_addr_c); }
                if amx_addr_p != 0 { release_fn(amx_ptr, amx_addr_p); }
            }
        }
    }
}
