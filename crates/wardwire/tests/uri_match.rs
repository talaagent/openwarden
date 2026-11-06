//! URI matching tables.

// Tables run long.
#![allow(clippy::too_many_lines)]

use wardwire::{MatchOptions, UriMatch, uri_matches};

use UriMatch::{Domain, Exact, Host, Never, RegularExpression, StartsWith};

fn check(table: &[(&str, Option<UriMatch>, &str, bool)], opts: &MatchOptions) {
    for &(login, m, page, want) in table {
        assert_eq!(
            uri_matches(login, m, page, opts),
            want,
            "{login:?} {m:?} vs {page:?}"
        );
    }
}

#[test]
fn domain() {
    check(
        &[
            (
                "https://example.com",
                Some(Domain),
                "https://example.com/login",
                true,
            ),
            (
                "https://example.com",
                Some(Domain),
                "https://www.example.com/",
                true,
            ),
            (
                "https://login.example.com",
                Some(Domain),
                "https://app.example.com",
                true,
            ),
            (
                "example.com",
                Some(Domain),
                "https://sub.example.com/x?y",
                true,
            ),
            (
                "https://example.com",
                Some(Domain),
                "http://example.com",
                false,
            ),
            (
                "http://example.com",
                Some(Domain),
                "https://example.com",
                true,
            ),
            (
                "https://example.com:8443",
                Some(Domain),
                "https://example.com",
                true,
            ),
            (
                "https://EXAMPLE.com",
                Some(Domain),
                "https://example.COM",
                true,
            ),
            (
                "https://example.com",
                Some(Domain),
                "https://example.org",
                false,
            ),
            (
                "https://example.com",
                Some(Domain),
                "https://example.com.evil.net",
                false,
            ),
            (
                "https://notexample.com",
                Some(Domain),
                "https://example.com",
                false,
            ),
            // Public suffixes: two different registrable domains.
            ("https://a.co.uk", Some(Domain), "https://b.co.uk", false),
            (
                "https://shop.example.co.uk",
                Some(Domain),
                "https://example.co.uk",
                true,
            ),
            (
                "https://alice.github.io",
                Some(Domain),
                "https://bob.github.io",
                false,
            ),
            // IPs and single-label hosts match only themselves.
            (
                "http://192.168.1.10",
                Some(Domain),
                "http://192.168.1.10:8080/",
                true,
            ),
            (
                "http://192.168.1.10",
                Some(Domain),
                "http://192.168.1.11",
                false,
            ),
            (
                "http://localhost:3000",
                Some(Domain),
                "http://localhost:4000",
                true,
            ),
            ("http://nas", Some(Domain), "http://router", false),
            // Not web URLs.
            (
                "androidapp://com.example",
                Some(Domain),
                "https://example.com",
                false,
            ),
            (
                "https://example.com",
                Some(Domain),
                "ftp://example.com",
                false,
            ),
            ("", Some(Domain), "https://example.com", false),
        ],
        &MatchOptions::default(),
    );
}

#[test]
fn default_is_domain_and_configurable() {
    check(
        &[
            ("https://example.com", None, "https://www.example.com", true),
            ("https://example.com", None, "https://example.org", false),
        ],
        &MatchOptions::default(),
    );
    let host = MatchOptions {
        default_match: Host,
        ..MatchOptions::default()
    };
    check(
        &[
            (
                "https://example.com",
                None,
                "https://www.example.com",
                false,
            ),
            ("https://example.com", None, "https://example.com/x", true),
        ],
        &host,
    );
}

#[test]
fn equivalent_domains() {
    let opts = MatchOptions {
        equivalent_domains: vec![vec!["example.com".into(), "example.net".into()]],
        ..MatchOptions::default()
    };
    check(
        &[
            (
                "https://example.com",
                Some(Domain),
                "https://login.example.net",
                true,
            ),
            ("https://example.net", None, "https://example.com", true),
            (
                "https://example.com",
                Some(Domain),
                "https://example.org",
                false,
            ),
            // Host matching ignores equivalence.
            (
                "https://example.com",
                Some(Host),
                "https://example.net",
                false,
            ),
        ],
        &opts,
    );
}

#[test]
fn host() {
    check(
        &[
            (
                "https://example.com",
                Some(Host),
                "https://example.com/path",
                true,
            ),
            (
                "https://example.com",
                Some(Host),
                "http://example.com",
                false,
            ),
            (
                "http://example.com",
                Some(Host),
                "https://example.com",
                true,
            ),
            (
                "https://example.com",
                Some(Host),
                "https://www.example.com",
                false,
            ),
            (
                "https://example.com:8443",
                Some(Host),
                "https://example.com:8443/x",
                true,
            ),
            (
                "https://example.com:8443",
                Some(Host),
                "https://example.com",
                false,
            ),
            (
                "https://example.com",
                Some(Host),
                "https://example.com:8443",
                false,
            ),
            ("example.com", Some(Host), "https://example.com", true),
        ],
        &MatchOptions::default(),
    );
}

#[test]
fn starts_with() {
    check(
        &[
            (
                "https://example.com/app",
                Some(StartsWith),
                "https://example.com/app/login",
                true,
            ),
            (
                "https://example.com/app",
                Some(StartsWith),
                "https://example.com/other",
                false,
            ),
            (
                "https://example.com",
                Some(StartsWith),
                "https://example.com.evil.net",
                false,
            ),
            (
                "https://example.com",
                Some(StartsWith),
                "https://example.com",
                true,
            ),
            (
                "https://example.com",
                Some(StartsWith),
                "https://example.com/login",
                true,
            ),
            (
                "https://example.com",
                Some(StartsWith),
                "https://example.com:8443/",
                true,
            ),
            (
                "https://example.com/app",
                Some(StartsWith),
                "https://example.com/app?next=1",
                true,
            ),
            (
                "https://example.com/app",
                Some(StartsWith),
                "https://example.com/app#top",
                true,
            ),
            (
                "https://example.com/app",
                Some(StartsWith),
                "https://example.com/application",
                false,
            ),
            (
                "https://example.com/",
                Some(StartsWith),
                "https://example.com/anything",
                true,
            ),
            (
                "https://example.com/search?",
                Some(StartsWith),
                "https://example.com/search?q=1",
                true,
            ),
            (
                "https://example.com/app",
                Some(StartsWith),
                "http://example.com/app",
                false,
            ),
            ("", Some(StartsWith), "https://example.com", false),
        ],
        &MatchOptions::default(),
    );
}

#[test]
fn exact() {
    check(
        &[
            (
                "https://example.com/login",
                Some(Exact),
                "https://example.com/login",
                true,
            ),
            (
                "https://example.com/login",
                Some(Exact),
                "https://example.com/login?x=1",
                false,
            ),
            (
                "https://example.com/login",
                Some(Exact),
                "https://example.com/Login",
                false,
            ),
        ],
        &MatchOptions::default(),
    );
}

#[test]
fn regex_only_when_allowed() {
    let table = [
        (
            r"^https://([a-z]+\.)?example\.com/",
            Some(RegularExpression),
            "https://app.example.com/x",
            true,
        ),
        (
            r"^https://([a-z]+\.)?example\.com/",
            Some(RegularExpression),
            "https://EXAMPLE.com/",
            true,
        ),
        (
            r"^https://([a-z]+\.)?example\.com/",
            Some(RegularExpression),
            "https://example.org/",
            false,
        ),
        (
            r"(unclosed",
            Some(RegularExpression),
            "https://example.com/",
            false,
        ),
    ];
    let off: Vec<_> = table.iter().map(|&(l, m, p, _)| (l, m, p, false)).collect();
    check(&off, &MatchOptions::default());
    check(
        &table,
        &MatchOptions {
            allow_regex: true,
            ..MatchOptions::default()
        },
    );
}

#[test]
fn never() {
    check(
        &[(
            "https://example.com",
            Some(Never),
            "https://example.com",
            false,
        )],
        &MatchOptions::default(),
    );
}

#[test]
fn wire_numbers() {
    for (n, m) in [
        (0, Domain),
        (1, Host),
        (2, StartsWith),
        (3, Exact),
        (4, RegularExpression),
        (5, Never),
    ] {
        assert_eq!(UriMatch::from_wire(n), Some(m));
        assert_eq!(m.to_wire(), n);
    }
    assert_eq!(UriMatch::from_wire(6), None);
}

#[test]
fn lax_scheme_lets_https_logins_match_http_pages() {
    let lax = MatchOptions {
        strict_scheme: false,
        ..MatchOptions::default()
    };
    check(
        &[
            (
                "https://example.com",
                Some(Domain),
                "http://example.com",
                true,
            ),
            (
                "https://example.com",
                Some(Host),
                "http://example.com",
                true,
            ),
            // Starts-with and exact compare the whole URL, scheme included.
            (
                "https://example.com",
                Some(StartsWith),
                "http://example.com/",
                false,
            ),
        ],
        &lax,
    );
}
