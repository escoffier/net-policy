/// Tracks where a request's body ends, WITHOUT storing or exposing any of
/// its bytes -- this daemon's only consumer of parsed HTTP (microsegmentation
/// policy matching) needs correct framing so pipelined requests parse
/// correctly, not body content. See the design spec for why body content
/// isn't exposed.
pub enum BodyFraming {
    None,
    ContentLength(usize),
    ChunkedSize,
    ChunkedData(usize),
    ChunkedTrailer,
}

impl BodyFraming {
    pub fn start(content_length: Option<usize>, chunked: bool) -> BodyFraming {
        if chunked {
            BodyFraming::ChunkedSize
        } else {
            match content_length {
                Some(0) | None => BodyFraming::None,
                Some(n) => BodyFraming::ContentLength(n),
            }
        }
    }

    /// Consumes as much of `buf` as belongs to the body (advancing internal
    /// state), returning `(bytes_consumed, framing_complete)`. When
    /// `framing_complete` is false, the caller must call `advance` again
    /// with more data (starting from byte `bytes_consumed` onward -- the
    /// caller is expected to drain consumed bytes from its own buffer, as
    /// Task 5's `Http1Parser` does).
    pub fn advance(&mut self, buf: &[u8]) -> (usize, bool) {
        match self {
            BodyFraming::None => (0, true),
            BodyFraming::ContentLength(remaining) => {
                let take = (*remaining).min(buf.len());
                *remaining -= take;
                (take, *remaining == 0)
            }
            BodyFraming::ChunkedSize | BodyFraming::ChunkedData(_) | BodyFraming::ChunkedTrailer => {
                self.advance_chunked(buf)
            }
        }
    }

    fn advance_chunked(&mut self, buf: &[u8]) -> (usize, bool) {
        let mut pos = 0;
        loop {
            match self {
                BodyFraming::ChunkedSize => match find_crlf(&buf[pos..]) {
                    None => return (pos, false),
                    Some(line_len) => {
                        let line = &buf[pos..pos + line_len];
                        let hex_part = line.split(|&b| b == b';').next().unwrap_or(line);
                        let size = std::str::from_utf8(hex_part)
                            .ok()
                            .and_then(|s| usize::from_str_radix(s.trim(), 16).ok())
                            .unwrap_or(0);
                        pos += line_len + 2;
                        *self = if size == 0 { BodyFraming::ChunkedTrailer } else { BodyFraming::ChunkedData(size) };
                    }
                },
                BodyFraming::ChunkedData(remaining) => {
                    let available = buf.len() - pos;
                    let take = (*remaining).min(available);
                    pos += take;
                    *remaining -= take;
                    if *remaining > 0 {
                        return (pos, false);
                    }
                    match find_crlf(&buf[pos..]) {
                        None => return (pos, false),
                        Some(0) => {
                            pos += 2;
                            *self = BodyFraming::ChunkedSize;
                        }
                        Some(_) => return (pos, false),
                    }
                }
                BodyFraming::ChunkedTrailer => match find_crlf(&buf[pos..]) {
                    None => return (pos, false),
                    Some(0) => {
                        pos += 2;
                        return (pos, true);
                    }
                    Some(line_len) => {
                        pos += line_len + 2;
                    }
                },
                BodyFraming::None | BodyFraming::ContentLength(_) => unreachable!(),
            }
        }
    }
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_body_completes_immediately_consuming_nothing() {
        let mut f = BodyFraming::start(None, false);
        let (consumed, done) = f.advance(b"GET /next HTTP/1.1\r\n\r\n");
        assert_eq!(consumed, 0);
        assert!(done);
    }

    #[test]
    fn zero_content_length_completes_immediately() {
        let mut f = BodyFraming::start(Some(0), false);
        let (consumed, done) = f.advance(b"");
        assert_eq!(consumed, 0);
        assert!(done);
    }

    #[test]
    fn content_length_consumes_exactly_that_many_bytes() {
        let mut f = BodyFraming::start(Some(5), false);
        let (consumed, done) = f.advance(b"12345restofbuffer");
        assert_eq!(consumed, 5);
        assert!(done);
    }

    #[test]
    fn content_length_needs_more_data_across_calls() {
        let mut f = BodyFraming::start(Some(10), false);
        let (consumed1, done1) = f.advance(b"12345");
        assert_eq!(consumed1, 5);
        assert!(!done1);
        let (consumed2, done2) = f.advance(b"67890");
        assert_eq!(consumed2, 5);
        assert!(done2);
    }

    #[test]
    fn chunked_single_chunk_then_terminator() {
        let mut f = BodyFraming::start(None, true);
        let buf = b"5\r\nhello\r\n0\r\n\r\n";
        let (consumed, done) = f.advance(buf);
        assert_eq!(consumed, buf.len());
        assert!(done);
    }

    #[test]
    fn chunked_multiple_chunks() {
        let mut f = BodyFraming::start(None, true);
        let buf = b"3\r\nfoo\r\n3\r\nbar\r\n0\r\n\r\n";
        let (consumed, done) = f.advance(buf);
        assert_eq!(consumed, buf.len());
        assert!(done);
    }

    #[test]
    fn chunked_needs_more_data_mid_chunk() {
        let mut f = BodyFraming::start(None, true);
        let (consumed1, done1) = f.advance(b"5\r\nhel");
        assert_eq!(consumed1, 6); // consumed the size line "5\r\n", 3 of the 5 data bytes
        assert!(!done1);
        let (consumed2, done2) = f.advance(b"lo\r\n0\r\n\r\n");
        assert_eq!(consumed2, 9);
        assert!(done2);
    }

    #[test]
    fn chunked_with_trailer_headers() {
        let mut f = BodyFraming::start(None, true);
        let buf = b"0\r\nX-Trailer: value\r\n\r\n";
        let (consumed, done) = f.advance(buf);
        assert_eq!(consumed, buf.len());
        assert!(done);
    }
}
