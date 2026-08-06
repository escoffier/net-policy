use crate::ffi::SharedFiveTuple;
use crate::ffi_raw::*;
use std::ffi::c_void;
use std::io;
use std::net::Ipv4Addr;
use std::os::raw::c_int;

/// Matches net-policy.cpp's `int family = AF_INET;` (sys/socket.h's AF_INET,
/// which is 2 on Linux for every architecture).
const AF_INET: u8 = 2;

/// inet_addr()'s failure value. SetAcceptMark used inet_addr() directly and
/// fed its result straight into nfct_set_attr_u32 without checking it, so a
/// non-empty-but-unparseable address ended up setting the filter attribute to
/// 0xffffffff -- a filter that matches nothing. Reproducing that exactly
/// matters: *skipping* the attribute instead would silently widen the filter
/// and force-update marks on connections the original code left alone.
const INADDR_NONE: u32 = u32::MAX;

/// The data pointer handed to nfct_callback_register, in its own heap
/// allocation owned by ConntrackSession.
///
/// The three handles the callback needs are duplicated here rather than having
/// the callback reconstitute a `&mut ConntrackSession` from the userdata
/// pointer. That matters because the callback only ever runs synchronously
/// from inside `nfct_query`, which `set_accept_mark(&mut self)` calls -- so a
/// `&mut ConntrackSession` built inside the callback would alias the `&mut
/// self` borrow still live on the stack below it. Giving the callback its own
/// allocation removes that aliasing question entirely instead of arguing about
/// whether it is benign.
///
/// These pointers are written exactly once, in `open_conntrack_session`, and
/// never mutated afterwards.
struct CallbackData {
    filter: *mut nf_conntrack,       // was NFQ_RES_INFO::nfct_
    update: *mut nf_conntrack,       // was ::nfct_cb_
    update_handle: *mut nfct_handle, // was ::nfct_cb_hd_
}

pub struct ConntrackSession {
    filter: *mut nf_conntrack,       // was NFQ_RES_INFO::nfct_
    update: *mut nf_conntrack,       // was ::nfct_cb_
    query_handle: *mut nfct_handle,  // was ::nfct_hd_
    update_handle: *mut nfct_handle, // was ::nfct_cb_hd_
    /// Owned (Box::into_raw); freed in Drop after the C resources are torn
    /// down, so the callback can no longer fire by then.
    cb_data: *mut CallbackData,
}

fn io_err(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, msg)
}

pub fn open_conntrack_session() -> io::Result<Box<ConntrackSession>> {
    // Mirrors OpenConntrack's (net-policy.cpp:1085-1111) exact allocation
    // order and its GOTO_ERROR cleanup-everything-allocated-so-far-then-fail
    // shape, translated to early Err returns with matching manual cleanup
    // (Rust has no goto, and ConntrackSession's own Drop cannot run yet since
    // it has not been fully constructed).
    let filter = unsafe { nfct_new() };
    if filter.is_null() {
        return Err(io_err("new nf conntrack failed"));
    }
    let query_handle = unsafe { nfct_open() };
    if query_handle.is_null() {
        unsafe { nfct_destroy(filter) };
        return Err(io_err("open nf conntrack failed"));
    }
    let update = unsafe { nfct_new() };
    if update.is_null() {
        unsafe {
            nfct_destroy(filter);
            nfct_close(query_handle);
        }
        return Err(io_err("new nf conntrack cb failed"));
    }
    let update_handle = unsafe { nfct_open() };
    if update_handle.is_null() {
        unsafe {
            nfct_destroy(filter);
            nfct_close(query_handle);
            nfct_destroy(update);
        }
        return Err(io_err("open nf conntrack cb failed"));
    }

    let cb_data = Box::into_raw(Box::new(CallbackData { filter, update, update_handle }));

    // Matches OpenConntrack's single one-time registration: NFCT_T_ALL, on the
    // *query* handle (nfct_hd_), with the callback userdata.
    unsafe {
        nfct_callback_register(
            query_handle,
            NFCT_T_ALL,
            update_net_session,
            cb_data as *mut c_void,
        );
    }

    Ok(Box::new(ConntrackSession { filter, update, query_handle, update_handle, cb_data }))
}

impl ConntrackSession {
    /// Ports SetAcceptMark (net-policy.cpp:417-457) 1:1. The original's
    /// `msgtype` parameter is intentionally absent: its only use there was the
    /// commented-out `nfct_callback_register` call on line 450 (registration
    /// happens once, at open time, instead).
    pub fn set_accept_mark(&mut self, tuple: &SharedFiveTuple, mark: u32) -> io::Result<()> {
        // SetAcceptMark's exact conditional attribute-setting: ATTR_MARK and
        // ATTR_ORIG_L3PROTO are unconditional, everything else only fires when
        // the corresponding tuple field is present.
        unsafe {
            nfct_set_attr_u32(self.filter, ATTR_MARK, mark);
            nfct_set_attr_u8(self.filter, ATTR_ORIG_L3PROTO, AF_INET);
            if tuple.proto > 0 {
                // The original wrote ATTR_L4PROTO, which libnetfilter_conntrack.h:85
                // declares as a literal alias of ATTR_ORIG_L4PROTO
                // (`ATTR_L4PROTO = ATTR_ORIG_L4PROTO, /* alias */`), so this is
                // the same attribute under its canonical name.
                nfct_set_attr_u8(self.filter, ATTR_ORIG_L4PROTO, tuple.proto);
            }
            if !tuple.src_addr.is_empty() {
                nfct_set_attr_u32(self.filter, ATTR_ORIG_IPV4_SRC, inet_addr(&tuple.src_addr));
            }
            if !tuple.dst_addr.is_empty() {
                nfct_set_attr_u32(self.filter, ATTR_ORIG_IPV4_DST, inet_addr(&tuple.dst_addr));
            }
            if tuple.src_port > 0 {
                nfct_set_attr_u16(self.filter, ATTR_ORIG_PORT_SRC, tuple.src_port.to_be());
            }
            if tuple.dst_port > 0 {
                nfct_set_attr_u16(self.filter, ATTR_ORIG_PORT_DST, tuple.dst_port.to_be());
            }

            // `nfct_query(cth, NFCT_Q_DUMP, &family)` -- the dump drives
            // update_net_session once per returned conntrack entry.
            let family: c_int = AF_INET as c_int;
            let ret = nfct_query(
                self.query_handle,
                NFCT_Q_DUMP,
                &family as *const c_int as *const c_void,
            );
            if ret != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("nfct query failed: {}", io::Error::last_os_error()),
                ));
            }
        }
        Ok(())
    }
}

impl Drop for ConntrackSession {
    fn drop(&mut self) {
        // Mirrors ~NFQ_RES_INFO's conntrack teardown block
        // (rule-detail.cpp:124-131) in its exact order: destroy filter,
        // destroy update, close query handle, close update handle. All four
        // run unconditionally -- they are always non-null once a
        // ConntrackSession exists at all, since open_conntrack_session never
        // returns a partially constructed one.
        unsafe {
            nfct_destroy(self.filter);
            nfct_destroy(self.update);
            nfct_close(self.query_handle);
            nfct_close(self.update_handle);
            // Only after the handles are closed, so no in-flight callback can
            // still be holding this pointer.
            drop(Box::from_raw(self.cb_data));
        }
    }
}

/// inet_addr() equivalent: dotted-quad text to a network-byte-order u32, with
/// inet_addr()'s INADDR_NONE on failure. `Ipv4Addr::from_str` is the parser the
/// rest of this repo's Rust crates already use (see net_policy_engine), and it
/// accepts exactly the four-part dotted-quad form the daemon's five-tuples are
/// formatted in. It does reject inet_addr()'s legacy shorthand ("10.1") and
/// hex/octal forms, which then take the INADDR_NONE path -- unreachable for
/// addresses produced by this daemon's own packet parser.
fn inet_addr(text: &str) -> u32 {
    text.parse::<Ipv4Addr>().map(|addr| u32::from(addr).to_be()).unwrap_or(INADDR_NONE)
}

/// Ports UpdateNetSession (net-policy.cpp:374-414) 1:1. Registered once, at
/// session-open time, as the callback for NFCT_T_ALL on query_handle -- fires
/// once per conntrack entry set_accept_mark's NFCT_Q_DUMP query returns.
extern "C" fn update_net_session(
    _msg_type: NfcMsgType,
    ct: *mut nf_conntrack,
    data: *mut c_void,
) -> c_int {
    // UpdateNetSession's `if (!ct || !data) return NFCT_CB_CONTINUE;`.
    if ct.is_null() || data.is_null() {
        return NFCT_CB_CONTINUE;
    }
    // SAFETY: `data` is always the CallbackData pointer this same module
    // passed to nfct_callback_register in open_conntrack_session, still owned
    // and un-freed (Drop frees it only after closing the handles that could
    // invoke this callback). Its three fields are read, never written, and no
    // Rust reference to CallbackData is ever created here or anywhere else --
    // so this cannot alias the `&mut self` borrow held by the set_accept_mark
    // call that is synchronously driving this callback further down the stack.
    let cb = data as *const CallbackData;
    let filter = unsafe { (*cb).filter };
    let update = unsafe { (*cb).update };
    let update_handle = unsafe { (*cb).update_handle };

    unsafe {
        // `if (!nfct_cmp(obj, ct, NFCT_CMP_ORIG)) return NFCT_CB_CONTINUE;`
        //
        // nfct_cmp returns 1 when the objects are EQUAL and 0 when they are
        // not (libnetfilter_conntrack/api.c:1017 -- "If both conntrack object
        // are equal, this function returns 1, otherwise 0 is returned"), so a
        // zero return means "this entry does not match the filter, skip it".
        // Do not flip this condition.
        if nfct_cmp(filter, ct, NFCT_CMP_ORIG) == 0 {
            return NFCT_CB_CONTINUE;
        }
        // `mark = nfct_get_attr_u32(obj, ATTR_MARK); if (mark > 100) ...` --
        // note this reads the mark back off the *filter*, i.e. the value
        // set_accept_mark just wrote, not off the matched entry.
        let mark = nfct_get_attr_u32(filter, ATTR_MARK);
        if mark > 100 {
            return NFCT_CB_CONTINUE;
        }
        nfct_copy(update, ct, NFCT_CP_ORIG);
        nfct_set_attr_u32(update, ATTR_MARK, mark);
        // `/* do not send NFCT_Q_UPDATE if ct appears unchanged */
        //  if (nfct_cmp(tmp, ct, NFCT_CMP_ALL | NFCT_CMP_MASK)) return ...;`
        // -- same polarity as above: a NONZERO return means equal/unchanged,
        // and unchanged is what gets skipped.
        if nfct_cmp(update, ct, NFCT_CMP_ALL | NFCT_CMP_MASK) != 0 {
            return NFCT_CB_CONTINUE;
        }
        let ret = nfct_query(update_handle, NFCT_Q_UPDATE, update as *const c_void);
        if ret < 0 {
            // Stands in for the original's LOG_E; matches the pattern the
            // other Rust crates here use, since Rust cannot reach the C++
            // LOG_* macros (see net_nfq, waf_rules_core, net_policy_events).
            eprintln!("net_conntrack: Operation failed: update mark failed.");
        }
    }
    NFCT_CB_CONTINUE
}

#[cfg(test)]
mod tests {
    use super::inet_addr;

    #[test]
    fn inet_addr_matches_c_inet_addr_for_dotted_quads() {
        // 127.0.0.1 in network byte order.
        assert_eq!(inet_addr("127.0.0.1"), u32::from_be_bytes([127, 0, 0, 1]).to_be());
        assert_eq!(inet_addr("0.0.0.0"), 0);
        assert_eq!(inet_addr("255.255.255.255"), u32::MAX);
        assert_eq!(inet_addr("10.1.2.3"), u32::from_be_bytes([10, 1, 2, 3]).to_be());
    }

    #[test]
    fn inet_addr_returns_inaddr_none_on_garbage() {
        // Matches inet_addr()'s own failure value, which SetAcceptMark fed
        // into the filter unchecked -- a filter that matches nothing.
        assert_eq!(inet_addr("not-an-address"), u32::MAX);
        assert_eq!(inet_addr("999.0.0.1"), u32::MAX);
    }
}
