use crate::ffi::{NfqMessage, NfqVerdict};
use std::collections::HashMap;

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

    /// Drains every message currently available without blocking --
    /// mirrors nfq_handle_packet's behavior of dispatching every message
    /// found in one read() buffer, since a single epoll wakeup can carry
    /// more than one queued packet.
    pub fn recv_batch(&mut self) -> std::io::Result<Vec<NfqMessage>> {
        let mut out = Vec::new();
        loop {
            match self.inner.recv() {
                Ok(msg) => {
                    let ffi_msg = NfqMessage {
                        id: msg.get_packet_id(),
                        payload: msg.get_payload().to_vec(),
                        nfmark: msg.get_nfmark(),
                    };
                    self.pending.insert(ffi_msg.id, msg);
                    out.push(ffi_msg);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        Ok(out)
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
