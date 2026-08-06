mod ffi_raw;
mod session;

pub use session::{open_conntrack_session, ConntrackSession};

#[cxx::bridge(namespace = "net_conntrack")]
mod ffi {
    /// The subset of C++'s FiveTuple that SetAcceptMark actually read.
    /// Addresses stay in their dotted-quad string form, matching FiveTuple's
    /// own `src_addr_`/`dst_addr_` std::strings.
    pub struct SharedFiveTuple {
        proto: u8,
        src_addr: String,
        dst_addr: String,
        src_port: u16,
        dst_port: u16,
    }

    extern "Rust" {
        type ConntrackSession;

        fn open_conntrack_session() -> Result<Box<ConntrackSession>>;
        fn set_accept_mark(
            self: &mut ConntrackSession, tuple: &SharedFiveTuple, mark: u32,
        ) -> Result<()>;
    }
}
