use crate::request_target::parse_request_target;

const MAX_HEADERS: usize = 100;

pub struct HeaderParseResult {
    pub method: String,
    pub path: String,
    pub host: String,
    pub fields: Vec<(String, String)>,
    pub content_length: Option<usize>,
    pub chunked: bool,
    pub consumed: usize,
}

/// Attempts to parse one complete HTTP/1.x request-line + header block from
/// the start of `buf`. `Ok(None)` means the buffer holds a valid prefix of a
/// request but not yet a complete header block (caller should wait for more
/// data via a later call). `Err(())` means the input is malformed -- this
/// includes both genuinely invalid syntax and MAX_HEADERS being exceeded
/// (httparse's `TooManyHeaders`). Unlike llhttp (which has no header-count
/// limit), httparse requires a fixed-size header array up front, so some
/// bound is unavoidable here; MAX_HEADERS is set well above what any real
/// client sends. A request that legitimately exceeds it is treated the same
/// as any other malformed message: this one message fails, and the caller
/// (`Http1Parser::dispatch`) resets and resyncs on the next message rather
/// than wedging the connection.
pub fn try_parse_headers(buf: &[u8]) -> Result<Option<HeaderParseResult>, ()> {
    let mut raw_headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut raw_headers);
    let consumed = match req.parse(buf) {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) => return Ok(None),
        Err(_) => return Err(()),
    };

    let method = req.method.unwrap_or("").to_string();
    let raw_target = req.path.unwrap_or("");
    let target = parse_request_target(raw_target);

    let mut fields = Vec::with_capacity(req.headers.len());
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for h in req.headers.iter() {
        let name = h.name.to_string();
        let value = String::from_utf8_lossy(h.value).into_owned();
        if name.eq_ignore_ascii_case("content-length") {
            let parsed: usize = value.trim().parse().map_err(|_| ())?;
            if let Some(existing) = content_length {
                if existing != parsed {
                    // Conflicting Content-Length values on the same
                    // message -- a classic request-smuggling vector.
                    // Reject rather than silently pick one.
                    return Err(());
                }
            }
            content_length = Some(parsed);
        } else if name.eq_ignore_ascii_case("transfer-encoding") && value.trim().eq_ignore_ascii_case("chunked") {
            chunked = true;
        }
        fields.push((name, value));
    }

    if chunked && content_length.is_some() {
        // Content-Length and Transfer-Encoding: chunked both present is
        // itself a request-smuggling vector (RFC 7230 SS3.3.3) -- reject
        // rather than silently letting chunked win.
        return Err(());
    }

    let host = resolve_host(&target.host, &fields);

    Ok(Some(HeaderParseResult {
        method,
        path: target.path,
        host,
        fields,
        content_length,
        chunked,
        consumed,
    }))
}

/// Mirrors http/http1/codec.cc's exact host-resolution priority: an
/// absolute-form request-target's host always wins (`target_host` is
/// already non-empty only in that case -- see request_target.rs); otherwise
/// fall back to the Host header with a trailing `:port` stripped by finding
/// the LAST `:` in the value, matching the old code's
/// `host_.find_last_of(":")` exactly, including its non-awareness of IPv6
/// literal hosts in brackets (not fixed here, same limitation as before).
fn resolve_host(target_host: &str, fields: &[(String, String)]) -> String {
    if !target_host.is_empty() {
        return target_host.to_string();
    }
    for (name, value) in fields {
        if name.eq_ignore_ascii_case("host") {
            return match value.rfind(':') {
                Some(idx) => value[..idx].to_string(),
                None => value.clone(),
            };
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_input_returns_none() {
        let buf = b"GET / HTTP/1.1\r\nHost: example";
        assert!(try_parse_headers(buf).unwrap().is_none());
    }

    #[test]
    fn origin_form_with_host_header() {
        let buf = b"PUT /internal/platform/waf/service?cluster=123 HTTP/1.1\r\nHost: abc.com:9090\r\nContent-Type: application/json\r\nContent-Length: 39\r\n\r\n";
        let result = try_parse_headers(buf).unwrap().unwrap();
        assert_eq!(result.method, "PUT");
        assert_eq!(result.path, "/internal/platform/waf/service");
        assert_eq!(result.host, "abc.com");
        assert_eq!(result.content_length, Some(39));
        assert!(!result.chunked);
        assert_eq!(result.consumed, buf.len());
        let host_field = result.fields.iter().find(|(n, _)| n.eq_ignore_ascii_case("host"));
        assert_eq!(host_field.map(|(_, v)| v.as_str()), Some("abc.com:9090"));
    }

    #[test]
    fn absolute_form_host_wins_over_host_header() {
        let buf = b"GET https://1.2.3.4:8888/foo HTTP/1.1\r\nHost: other.example.com\r\n\r\n";
        let result = try_parse_headers(buf).unwrap().unwrap();
        assert_eq!(result.host, "1.2.3.4");
        assert_eq!(result.path, "/foo");
    }

    #[test]
    fn origin_form_no_host_header_yields_empty_host() {
        let buf = b"GET /foo HTTP/1.1\r\n\r\n";
        let result = try_parse_headers(buf).unwrap().unwrap();
        assert_eq!(result.host, "");
    }

    #[test]
    fn host_header_without_port_is_not_truncated() {
        let buf = b"GET /foo HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = try_parse_headers(buf).unwrap().unwrap();
        assert_eq!(result.host, "example.com");
    }

    #[test]
    fn chunked_transfer_encoding_detected() {
        let buf = b"POST /foo HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n";
        let result = try_parse_headers(buf).unwrap().unwrap();
        assert!(result.chunked);
        assert_eq!(result.content_length, None);
    }

    #[test]
    fn malformed_request_line_is_an_error() {
        let buf = b"NOT A REQUEST\r\n\r\n";
        assert!(try_parse_headers(buf).is_err());
    }

    #[test]
    fn a_request_with_80_headers_parses_successfully() {
        let mut buf = String::from("GET /foo HTTP/1.1\r\n");
        for i in 0..80 {
            buf.push_str(&format!("X-Custom-{i}: value{i}\r\n"));
        }
        buf.push_str("\r\n");
        let result = try_parse_headers(buf.as_bytes()).unwrap().unwrap();
        assert_eq!(result.path, "/foo");
        assert_eq!(result.fields.len(), 80);
    }

    #[test]
    fn a_request_with_far_too_many_headers_is_an_error() {
        let mut buf = String::from("GET /foo HTTP/1.1\r\n");
        for i in 0..500 {
            buf.push_str(&format!("X-Custom-{i}: value{i}\r\n"));
        }
        buf.push_str("\r\n");
        assert!(try_parse_headers(buf.as_bytes()).is_err());
    }

    #[test]
    fn unparseable_content_length_is_an_error() {
        let buf = b"POST /foo HTTP/1.1\r\nContent-Length: abc\r\n\r\n";
        assert!(try_parse_headers(buf).is_err());
    }

    #[test]
    fn negative_content_length_is_an_error() {
        let buf = b"POST /foo HTTP/1.1\r\nContent-Length: -1\r\n\r\n";
        assert!(try_parse_headers(buf).is_err());
    }

    #[test]
    fn conflicting_duplicate_content_length_is_an_error() {
        let buf = b"POST /foo HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 10\r\n\r\n";
        assert!(try_parse_headers(buf).is_err());
    }

    #[test]
    fn identical_duplicate_content_length_is_allowed() {
        let buf = b"POST /foo HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n";
        let result = try_parse_headers(buf).unwrap().unwrap();
        assert_eq!(result.content_length, Some(5));
    }

    #[test]
    fn content_length_and_chunked_together_is_an_error() {
        let buf = b"POST /foo HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert!(try_parse_headers(buf).is_err());
    }
}
