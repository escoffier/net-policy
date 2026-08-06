#![allow(non_camel_case_types)]

use std::os::raw::{c_int, c_uint, c_void};

/// Opaque -- this codebase never reads nf_conntrack's fields directly, only
/// passes pointers to it through the library's own accessor functions.
#[repr(C)]
pub struct nf_conntrack {
    _private: [u8; 0],
}

/// Opaque -- same reasoning as nf_conntrack.
#[repr(C)]
pub struct nfct_handle {
    _private: [u8; 0],
}

/// NFC_MSG_TYPE (libnetfilter_conntrack.h:196-214) is a plain C enum with no
/// explicit underlying type -- c_int matches this platform's (GCC/Clang on
/// Linux x86_64/aarch64) default enum representation. NFCT_T_ERROR's value,
/// (1 << 31), is bit-identical whether read as i32 or u32; nothing in this
/// crate compares NfcMsgType with `<` or `>`, only bitwise `&`, so signedness
/// cannot produce a wrong answer here.
pub type NfcMsgType = c_int;

// Verified against libnetfilter_conntrack.h at plan-writing time -- re-verify
// against the header before trusting these if this file is ever touched
// without re-reading it.
pub const NFCT_T_ALL: NfcMsgType = 7; // NEW(1) | UPDATE(2) | DESTROY(4)
pub const NFCT_CB_CONTINUE: c_int = 1;

pub const NFCT_CMP_ALL: c_uint = 0;
pub const NFCT_CMP_ORIG: c_uint = 1; // 1 << 0
pub const NFCT_CMP_MASK: c_uint = 32; // 1 << 5

pub const NFCT_CP_ORIG: c_uint = 1; // 1 << 0

pub const NFCT_Q_UPDATE: c_uint = 1;
pub const NFCT_Q_DUMP: c_uint = 5;

pub const ATTR_ORIG_IPV4_SRC: c_int = 0;
pub const ATTR_ORIG_IPV4_DST: c_int = 1;
pub const ATTR_ORIG_PORT_SRC: c_int = 8;
pub const ATTR_ORIG_PORT_DST: c_int = 9;
pub const ATTR_ORIG_L3PROTO: c_int = 15;
pub const ATTR_ORIG_L4PROTO: c_int = 17;
pub const ATTR_MARK: c_int = 25;

pub type UpdateCallback =
    extern "C" fn(NfcMsgType, *mut nf_conntrack, *mut c_void) -> c_int;

extern "C" {
    pub fn nfct_new() -> *mut nf_conntrack;
    pub fn nfct_destroy(ct: *mut nf_conntrack);
    pub fn nfct_open() -> *mut nfct_handle; // zero args in THIS vendored header
    pub fn nfct_close(cth: *mut nfct_handle) -> c_int;
    pub fn nfct_callback_register(
        h: *mut nfct_handle,
        type_: NfcMsgType,
        cb: UpdateCallback,
        data: *mut c_void,
    ) -> c_int;
    pub fn nfct_cmp(ct1: *const nf_conntrack, ct2: *const nf_conntrack, flags: c_uint) -> c_int;
    pub fn nfct_copy(dest: *mut nf_conntrack, src: *const nf_conntrack, flags: c_uint);
    pub fn nfct_get_attr_u32(ct: *const nf_conntrack, type_: c_int) -> u32;
    pub fn nfct_set_attr_u8(ct: *mut nf_conntrack, type_: c_int, value: u8);
    pub fn nfct_set_attr_u16(ct: *mut nf_conntrack, type_: c_int, value: u16);
    pub fn nfct_set_attr_u32(ct: *mut nf_conntrack, type_: c_int, value: u32);
    pub fn nfct_query(h: *mut nfct_handle, query: c_uint, data: *const c_void) -> c_int;
}
