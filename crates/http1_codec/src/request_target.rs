/// A parsed HTTP/1.x request-target, per RFC 7230 §5.3. Only origin-form
/// (`/path`) and absolute-form (`scheme://host[:port]/path`) produce a
/// non-empty `host` -- the only two forms `http/url.cc`'s `Url::initialize`
/// (what this replaces) ever did. Authority-form (bare `host:port`, used
/// only by CONNECT) and asterisk-form (`*`, used only by OPTIONS) are not
/// exercised by any existing test or caller; they fall through to the
/// origin-form branch below (empty host), matching what an unrecognized
/// target produced in the old code path.
pub struct RequestTarget {
    pub host: String,
    pub path: String,
}

pub fn parse_request_target(target: &str) -> RequestTarget {
    if let Some(rest) = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
    {
        let authority_end = rest.find('/').unwrap_or(rest.len());
        let authority = &rest[..authority_end];
        let host = authority.split(':').next().unwrap_or("").to_string();
        let path_and_query = &rest[authority_end..];
        let path = path_and_query.split('?').next().unwrap_or("").to_string();
        RequestTarget { host, path }
    } else {
        let path = target.split('?').next().unwrap_or("").to_string();
        RequestTarget { host: String::new(), path }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_form_extracts_host_and_strips_port_and_query() {
        let t = parse_request_target("https://1.2.3.4:8888/internal/platform/waf/service?cluster=123");
        assert_eq!(t.host, "1.2.3.4");
        assert_eq!(t.path, "/internal/platform/waf/service");
    }

    #[test]
    fn absolute_form_http_scheme_also_recognized() {
        let t = parse_request_target("http://example.com/foo");
        assert_eq!(t.host, "example.com");
        assert_eq!(t.path, "/foo");
    }

    #[test]
    fn absolute_form_without_port_extracts_host() {
        let t = parse_request_target("https://example.com/foo");
        assert_eq!(t.host, "example.com");
        assert_eq!(t.path, "/foo");
    }

    #[test]
    fn origin_form_has_empty_host_and_strips_query() {
        let t = parse_request_target("/internal/platform/waf/service?cluster=123");
        assert_eq!(t.host, "");
        assert_eq!(t.path, "/internal/platform/waf/service");
    }

    #[test]
    fn origin_form_no_query() {
        let t = parse_request_target("/foo/bar");
        assert_eq!(t.host, "");
        assert_eq!(t.path, "/foo/bar");
    }
}
