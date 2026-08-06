use crate::ffi::{NfqMessage, NfqVerdict};
use std::collections::HashMap;

/// Upper bound on how many messages a single recv_batch() call drains.
///
/// Every drained message stays alive in `pending` until C++ verdicts it,
/// and a live nfq::Message pins the Queue's whole receive buffer: the
/// crate reuses that buffer via Arc::get_mut only when no Message still
/// references it, so once one message is pending, every further recv()
/// allocates a fresh ~68 KB buffer ((min(page_size, 8192) + 65535 + 3)/4
/// words). Draining unbounded would therefore hold N * ~68 KB at once --
/// with the kernel's default queue_maxlen of 1024 (this code never
/// overrides it), up to ~70 MB transient per queue. The cap also keeps one
/// wakeup's work bounded so the shared epoll loop can service its other
/// sources (gRPC dispatch eventfd, reaper timerfd, post-notification
/// socket) instead of being pinned until a busy queue is fully drained.
const MAX_BATCH: usize = 64;

pub struct NfqQueue {
    inner: nfq::Queue,
    // Verdict issuance in the `nfq` crate requires the original `Message`
    // object, not just its id (unlike libnetfilter_queue's id-only
    // nfq_set_verdict2). recv_batch() stashes each Message here, keyed by
    // its own packet id, so verdict()/verdict_with_mark() can look it back
    // up -- the C++-facing API stays id-based, matching every existing
    // nfq_set_verdict(2) call site's shape.
    pending: HashMap<u32, nfq::Message>,
}

impl NfqQueue {
    pub fn open(queue_num: u16) -> std::io::Result<Self> {
        let mut inner = nfq::Queue::open()?;
        inner.bind(queue_num)?;
        // 0xffff: full packet copies, matching nfq_set_mode(qh,
        // NFQNL_COPY_PACKET, 0xffff) in the C code this replaces.
        inner.set_copy_range(queue_num, 0xffff)?;
        inner.set_nonblocking(true);
        Ok(NfqQueue { inner, pending: HashMap::new() })
    }

    pub fn fd(&self) -> i32 {
        self.inner.as_raw_fd()
    }

    /// Drains up to MAX_BATCH messages currently available without
    /// blocking, since a single epoll wakeup can carry more than one queued
    /// packet. Stops early at the first WouldBlock (queue empty), and never
    /// returns more than MAX_BATCH even when the queue holds more: the
    /// epoll registration is level-triggered (EPOLLIN, no EPOLLET, see
    /// AddEpollEvent in net-policy.cpp), so a partial drain re-fires
    /// immediately and the rest is picked up on the next wakeup -- nothing
    /// is lost or delayed beyond one loop iteration.
    pub fn recv_batch(&mut self) -> std::io::Result<Vec<NfqMessage>> {
        // Split borrow: drain_batch needs &mut pending and a recv closure
        // holding &mut inner at the same time.
        let inner = &mut self.inner;
        drain_batch(
            &mut self.pending,
            || inner.recv(),
            |msg: &nfq::Message| NfqMessage {
                id: msg.get_packet_id(),
                payload: msg.get_payload().to_vec(),
                nfmark: msg.get_nfmark(),
            },
        )
    }

    pub fn verdict(&mut self, id: u32, v: NfqVerdict, payload: &[u8]) -> std::io::Result<()> {
        self.verdict_impl(id, v, None, payload)
    }

    pub fn verdict_with_mark(
        &mut self, id: u32, v: NfqVerdict, mark: u32, payload: &[u8],
    ) -> std::io::Result<()> {
        self.verdict_impl(id, v, Some(mark), payload)
    }

    fn verdict_impl(
        &mut self, id: u32, v: NfqVerdict, mark: Option<u32>, payload: &[u8],
    ) -> std::io::Result<()> {
        let mut msg = self.pending.remove(&id).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no pending nfq message with id {id}"),
            )
        })?;
        if let Some(m) = mark {
            msg.set_nfmark(m);
        }
        // Empty slice means "no NFQA_PAYLOAD attribute at all" (kernel keeps
        // the original payload), matching today's data_len=0/pkg=NULL calls
        // -- not a zero-length payload override.
        if !payload.is_empty() {
            msg.set_payload(payload.to_vec());
        }
        msg.set_verdict(match v {
            NfqVerdict::Accept => nfq::Verdict::Accept,
            NfqVerdict::Drop => nfq::Verdict::Drop,
            _ => unreachable!("NfqVerdict has exactly two variants"),
        });
        self.inner.verdict(msg)
    }
}

/// recv_batch()'s drain loop, factored out as a free function generic over
/// the message type purely so it can be unit-tested without a live kernel
/// queue: `nfq::Message` has no public constructor (its fields are raw
/// pointers into the crate's own receive buffer) and `nfq::Queue::recv()`
/// cannot be driven without CAP_NET_ADMIN, so the only way to exercise this
/// loop's own logic is to instantiate it over a fake message/source.
/// recv_batch() instantiates exactly this code with M = nfq::Message.
fn drain_batch<M>(
    pending: &mut HashMap<u32, M>, mut recv_one: impl FnMut() -> std::io::Result<M>,
    describe: impl Fn(&M) -> NfqMessage,
) -> std::io::Result<Vec<NfqMessage>> {
    // `pending` is provably empty here in correct operation: NfqueueRcvData
    // calls recv_batch() once and verdicts every returned message (each
    // path through input_nfq_cb/output_nfq_cb issues exactly one verdict,
    // and verdict_impl removes the entry) before calling recv_batch()
    // again. It is NOT empty if a previous call returned early on a real
    // error, unwound out of the nfq crate's own attribute parser (several
    // assert!s in parse_msg/parse_attr fire on malformed netlink data), or
    // if a caller threw before verdicting: in those cases the messages
    // already stashed here never reached C++, so nothing will ever remove
    // them and each one pins a ~68 KB receive buffer for the process's
    // lifetime. Clearing here is a no-op on the happy path and bounds that
    // staleness to a single batch.
    //
    // Warn rather than debug_assert!: this is exactly the situation that
    // matters in the release build the daemon actually ships, where a
    // debug_assert compiles away to nothing, and eprintln! matches this
    // workspace's existing convention for FFI-side diagnostics that can't
    // reach the C++ LOG_* macros (see net_conntrack, net_policy_control,
    // net_policy_events).
    if !pending.is_empty() {
        eprintln!(
            "net_nfq: recv_batch found {} stale pending message(s) from an earlier failed \
             call; dropping them",
            pending.len()
        );
        pending.clear();
    }

    let mut out = Vec::new();
    while out.len() < MAX_BATCH {
        match recv_one() {
            Ok(msg) => {
                let ffi_msg = describe(&msg);
                pending.insert(ffi_msg.id, msg);
                out.push(ffi_msg);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Stand-in for nfq::Message; see drain_batch's doc comment for why the
    // real type can't be used here.
    struct FakeMsg {
        id: u32,
    }

    fn describe(m: &FakeMsg) -> NfqMessage {
        NfqMessage { id: m.id, payload: Vec::new(), nfmark: 0 }
    }

    fn would_block() -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::WouldBlock, "no more messages")
    }

    /// A source of `available` messages with consecutive ids starting at
    /// `first_id`, then WouldBlock forever -- the shape a real nonblocking
    /// nfq::Queue::recv() presents once its socket is drained.
    fn source(first_id: u32, available: u32) -> impl FnMut() -> std::io::Result<FakeMsg> {
        let mut next = first_id;
        let end = first_id + available;
        move || {
            if next < end {
                let msg = FakeMsg { id: next };
                next += 1;
                Ok(msg)
            } else {
                Err(would_block())
            }
        }
    }

    #[test]
    fn returns_everything_when_fewer_than_the_cap_are_available() {
        let mut pending = HashMap::new();
        let out = drain_batch(&mut pending, source(0, 3), describe).unwrap();
        assert_eq!(out.len(), 3);
        assert_eq!(pending.len(), 3);
    }

    #[test]
    fn caps_one_call_at_max_batch_and_resumes_on_the_next() {
        // 150 queued packets, well under the kernel's default queue_maxlen
        // of 1024 but well over the cap.
        let mut pending = HashMap::new();
        let mut src = source(0, 150);

        let first = drain_batch(&mut pending, &mut src, describe).unwrap();
        assert_eq!(first.len(), MAX_BATCH, "one call must not drain past the cap");
        assert_eq!(first[0].id, 0);
        assert_eq!(first[MAX_BATCH - 1].id, MAX_BATCH as u32 - 1);

        // Level-triggered epoll re-fires while data remains, so the next
        // call picks up exactly where this one stopped -- nothing dropped.
        pending.clear(); // stand-in for C++ verdicting the first batch
        let second = drain_batch(&mut pending, &mut src, describe).unwrap();
        assert_eq!(second.len(), MAX_BATCH);
        assert_eq!(second[0].id, MAX_BATCH as u32);

        pending.clear();
        let third = drain_batch(&mut pending, &mut src, describe).unwrap();
        assert_eq!(third.len(), 150 - 2 * MAX_BATCH);
        assert_eq!(third[0].id, 2 * MAX_BATCH as u32);

        pending.clear();
        let fourth = drain_batch(&mut pending, &mut src, describe).unwrap();
        assert!(fourth.is_empty());
    }

    #[test]
    fn a_mid_batch_error_propagates() {
        let mut pending = HashMap::new();
        let mut count = 0;
        let res = drain_batch(
            &mut pending,
            || {
                count += 1;
                if count <= 3 {
                    Ok(FakeMsg { id: count })
                } else {
                    // ENOSPC: what the nfq crate returns for a truncated
                    // netlink message. EINTR (NLM_F_DUMP_INTR) is the other
                    // real mid-batch error it can produce.
                    Err(std::io::Error::from_raw_os_error(libc_enospc()))
                }
            },
            describe,
        );
        // NfqMessage (a cxx shared struct) has no Debug impl, so unwrap_err
        // isn't available here.
        match res {
            Ok(_) => panic!("a non-WouldBlock error must not be swallowed"),
            Err(e) => assert_eq!(e.raw_os_error(), Some(libc_enospc())),
        }
    }

    #[test]
    fn stale_pending_entries_from_an_earlier_failed_call_are_dropped() {
        let mut pending = HashMap::new();

        // Call 1 dies mid-batch after three messages were already stashed
        // in `pending`. Those three never reached C++ (the partially built
        // Vec is discarded), so nothing will ever verdict them -- each one
        // pins a ~68 KB receive buffer until something clears it.
        let mut count = 0;
        let res = drain_batch(
            &mut pending,
            || {
                count += 1;
                if count <= 3 {
                    Ok(FakeMsg { id: 1000 + count })
                } else {
                    Err(std::io::Error::from_raw_os_error(libc_enospc()))
                }
            },
            describe,
        );
        assert!(res.is_err());
        assert_eq!(pending.len(), 3, "the failed call is expected to leave entries behind");

        // Call 2 must not inherit them: the map is provably empty at the
        // start of any correct recv_batch() call, so staleness is bounded
        // at one batch rather than leaking forever.
        let out = drain_batch(&mut pending, source(0, 2), describe).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(pending.len(), 2, "stale entries from the failed call must be gone");
        assert!(pending.keys().all(|id| *id < 1000));
    }

    fn libc_enospc() -> i32 {
        28
    }
}
