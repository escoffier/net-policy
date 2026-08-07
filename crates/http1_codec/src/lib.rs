mod body_framing;
mod header_parser;
mod request_target;

use body_framing::BodyFraming;

#[cxx::bridge(namespace = "http1_codec")]
mod ffi {
    #[derive(Default)]
    struct HeaderField {
        name: String,
        value: String,
    }

    #[derive(Default)]
    struct ParsedHeader {
        method: String,
        path: String,
        host: String,
        fields: Vec<HeaderField>,
        /// 0 = Continue (need more data to complete a message), 1 = Done
        /// (a message's headers just completed in this call), 2 = Error --
        /// mirrors http::ParseState's three variants exactly.
        parse_state: i32,
    }

    extern "Rust" {
        type Http1Parser;

        fn new_http1_parser() -> Box<Http1Parser>;
        fn dispatch(self: &mut Http1Parser, data: &[u8]) -> ParsedHeader;
    }
}

const PARSE_STATE_CONTINUE: i32 = 0;
const PARSE_STATE_DONE: i32 = 1;
const PARSE_STATE_ERROR: i32 = 2;

enum Phase {
    Headers,
    Body(BodyFraming),
}

pub struct Http1Parser {
    buf: Vec<u8>,
    phase: Phase,
}

fn new_http1_parser() -> Box<Http1Parser> {
    Box::new(Http1Parser::new())
}

impl Http1Parser {
    pub fn new() -> Self {
        Http1Parser { buf: Vec::new(), phase: Phase::Headers }
    }

    /// Feeds `data` in, advancing internal state. Accumulates across calls
    /// (TCP segments arrive in arbitrary chunks) -- mirrors llhttp_t's
    /// persistent-parser-state contract, reimplemented on top of httparse's
    /// one-shot-per-call API by re-parsing the accumulated buffer.
    ///
    /// If this single call's data contains more than one complete pipelined
    /// request, only the LAST one's parsed header is returned -- earlier
    /// ones in the same call are not surfaced. This matches the old
    /// llhttp-based C++ wrapper's behavior exactly (its `header_` member got
    /// overwritten on each new message within one `dispatch()` call; not
    /// something this migration fixes, see the design spec).
    ///
    /// A `Continue`-state result never carries forward a PRIOR call's
    /// completed header data (unlike the old C++, which left `header_`'s
    /// fields at whatever they last held). This is an intentional,
    /// behavior-preserving simplification: the only real caller
    /// (`net::ConnectionManager::DispatchMicroseg`) only reads `Header`'s
    /// fields when `parseState_ == Done`, discarding the result entirely
    /// otherwise -- so whether a discarded result carries stale data or
    /// fresh defaults is unobservable to every actual caller.
    pub fn dispatch(&mut self, data: &[u8]) -> ffi::ParsedHeader {
        self.buf.extend_from_slice(data);
        let mut result: Option<ffi::ParsedHeader> = None;

        loop {
            match &mut self.phase {
                Phase::Headers => match header_parser::try_parse_headers(&self.buf) {
                    Err(()) => {
                        return ffi::ParsedHeader { parse_state: PARSE_STATE_ERROR, ..Default::default() };
                    }
                    Ok(None) => break,
                    Ok(Some(parsed)) => {
                        let consumed = parsed.consumed;
                        let framing = BodyFraming::start(parsed.content_length, parsed.chunked);
                        result = Some(ffi::ParsedHeader {
                            method: parsed.method,
                            path: parsed.path,
                            host: parsed.host,
                            fields: parsed
                                .fields
                                .into_iter()
                                .map(|(name, value)| ffi::HeaderField { name, value })
                                .collect(),
                            parse_state: PARSE_STATE_DONE,
                        });
                        self.buf.drain(..consumed);
                        self.phase = Phase::Body(framing);
                    }
                },
                Phase::Body(framing) => match framing.advance(&self.buf) {
                    Err(()) => {
                        return ffi::ParsedHeader { parse_state: PARSE_STATE_ERROR, ..Default::default() };
                    }
                    Ok((consumed, complete)) => {
                        self.buf.drain(..consumed);
                        if !complete {
                            break;
                        }
                        self.phase = Phase::Headers;
                    }
                },
            }
        }

        result.unwrap_or_else(|| ffi::ParsedHeader { parse_state: PARSE_STATE_CONTINUE, ..Default::default() })
    }
}

#[cfg(test)]
mod integration_tests {
    use super::Http1Parser;

    const DONE: i32 = 1;
    const CONTINUE: i32 = 0;

    #[test]
    fn incremental_across_two_calls_matches_existing_cpp_test() {
        let mut p = Http1Parser::new();
        let r1 = p.dispatch(b"POST https://1.2.3.4:8888/internal/platform/waf/");
        assert_eq!(r1.parse_state, CONTINUE);
        assert_eq!(r1.method, "");
        assert_eq!(r1.path, "");
        assert_eq!(r1.host, "");

        let r2 = p.dispatch(b"service?cluster=123 HTTP/1.1\r\ncontent-length: 3\r\n\r\n123");
        assert_eq!(r2.parse_state, DONE);
        assert_eq!(r2.method, "POST");
        assert_eq!(r2.path, "/internal/platform/waf/service");
        assert_eq!(r2.host, "1.2.3.4");
    }

    #[test]
    fn single_call_matches_existing_cpp_test_dispatch1() {
        let mut p = Http1Parser::new();
        let put = b"PUT /internal/platform/waf/service?cluster=123 HTTP/1.1\r\nHost: abc.com:9090\r\nContent-Type: application/json\r\nContent-Length: 39\r\n\r\n{\n  \"id\": 94,\n\"name\": \"x\"\n}";
        let r = p.dispatch(put);
        assert_eq!(r.parse_state, DONE);
        assert_eq!(r.host, "abc.com");
        assert_eq!(r.path, "/internal/platform/waf/service");
    }

    #[test]
    fn pipelined_requests_in_one_call_returns_only_the_last() {
        let mut p = Http1Parser::new();
        let buf = b"GET /first HTTP/1.1\r\n\r\nGET /second HTTP/1.1\r\n\r\n";
        let r = p.dispatch(buf);
        assert_eq!(r.parse_state, DONE);
        assert_eq!(r.path, "/second");
    }

    #[test]
    fn chunked_body_does_not_corrupt_next_pipelined_request() {
        let mut p = Http1Parser::new();
        let buf = b"POST /upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nfoo\r\n0\r\n\r\nGET /next HTTP/1.1\r\n\r\n";
        let r = p.dispatch(buf);
        assert_eq!(r.parse_state, DONE);
        assert_eq!(r.path, "/next");
    }

    #[test]
    fn error_on_malformed_input() {
        let mut p = Http1Parser::new();
        let r = p.dispatch(b"NOT A REQUEST\r\n\r\n");
        assert_eq!(r.parse_state, 2 /* Error */);
    }

    #[test]
    fn error_on_malformed_chunked_body() {
        let mut p = Http1Parser::new();
        // Headers parse fine; the chunked body that follows violates the
        // chunked grammar (chunk-data not immediately followed by CRLF) --
        // this must surface as Error through the full dispatch() path, not
        // just at the body_framing unit-test level.
        let buf = b"POST /upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nfooXX\r\n0\r\n\r\n";
        let r = p.dispatch(buf);
        assert_eq!(r.parse_state, 2 /* Error */);
    }
}
