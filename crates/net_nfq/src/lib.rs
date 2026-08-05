mod netns;
mod queue;

pub use queue::NfqQueue;

#[cxx::bridge(namespace = "net_nfq")]
mod ffi {
    pub struct NfqMessage {
        id: u32,
        payload: Vec<u8>,
        nfmark: u32,
    }

    pub enum NfqVerdict {
        Accept,
        Drop,
    }

    extern "Rust" {
        type NfqQueue;

        fn open_queue(queue_num: u16) -> Result<Box<NfqQueue>>;
        fn fd(self: &NfqQueue) -> i32;
        fn recv_batch(self: &mut NfqQueue) -> Result<Vec<NfqMessage>>;
        fn verdict(self: &mut NfqQueue, id: u32, v: NfqVerdict, payload: &[u8]) -> Result<()>;
        fn verdict_with_mark(
            self: &mut NfqQueue, id: u32, v: NfqVerdict, mark: u32, payload: &[u8],
        ) -> Result<()>;

        fn set_ns(pid: i32, base_path: &str) -> Result<()>;
    }
}

fn open_queue(queue_num: u16) -> Result<Box<NfqQueue>, std::io::Error> {
    Ok(Box::new(NfqQueue::open(queue_num)?))
}

fn set_ns(pid: i32, base_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    netns::set_ns(pid, base_path)
}
