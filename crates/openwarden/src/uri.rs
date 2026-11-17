//! Login URI matching, with Bitwarden's match types.
//!
//! | type | name        | matches when                                              |
//! |------|-------------|-----------------------------------------------------------|
//! | 0    | domain      | the base (registrable) domains are equal                  |
//! | 1    | host        | the hosts and ports are equal                             |
//! | 2    | starts with | the page URL starts with the login URI, at a boundary     |
//! | 3    | exact       | the page URL equals the login URI                         |
//! | 4    | regex       | the login URI, as a case-insensitive regex, matches       |
//! | 5    | never       | never                                                     |
//!
//! A login URI with no match type takes [`MatchOptions::default_match`]
//! (domain, as in Bitwarden). The base domain comes from the public suffix
//! list (`psl`): `login.example.co.uk` and `www.example.co.uk` share
//! `example.co.uk`; IP addresses and single-label hosts (`localhost`) are
//! their own base domain. A login URI without a scheme is read as
//! `http://`, as Bitwarden does. Domain and host matching only consider
//! `http` and `https` URLs, so an `androidapp://` URI never matches a page.
//! With [`MatchOptions::strict_scheme`] (the default), an `https` login URI
//! never matches an `http` page by domain or host: a password saved for
//! the secure site isn't offered to a plain-text one. (An `http` login URI
//! still matches an `https` page.)
//!
//! Starts-with needs a boundary: the page must equal the login URI, or the
//! login URI must end in `/`, `?`, `#` or `&`, or the rest of the page must
//! start with `/`, `?` or `#`, or with `:` and a port number (digits, then
//! the end or `/`, `?`, `#`). So `https://bank.com` matches
//! `https://bank.com/login` and `https://bank.com:8443/`, but not
//! `https://bank.com.evil.net/`. (This is stricter than Bitwarden.)
//!
//! A page URL with userinfo (`https://bank.com:x@evil.net/`, whose host is
//! `evil.net`) never matches, in any mode: it is a classic way to make a URL
//! look like another site's.
//!
//! Regex matching is off unless [`MatchOptions::allow_regex`] is set: a
//! regex in a login URI is the vault's data, and with it off a regex URI
//! never matches.

use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use regex_automata::{meta, util::syntax};
use url::{Host, Url};

/// A login URI's match type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UriMatch {
    /// 0: the base domain.
    Domain,
    /// 1: the host and port.
    Host,
    /// 2: the page URL starts with the login URI.
    StartsWith,
    /// 3: the page URL equals the login URI.
    Exact,
    /// 4: the login URI is a regex over the page URL.
    RegularExpression,
    /// 5: never matches.
    Never,
}

impl UriMatch {
    /// From the wire's number; `None` for an unknown one.
    pub fn from_wire(n: u8) -> Option<Self> {
        Some(match n {
            0 => Self::Domain,
            1 => Self::Host,
            2 => Self::StartsWith,
            3 => Self::Exact,
            4 => Self::RegularExpression,
            5 => Self::Never,
            _ => return None,
        })
    }

    /// The wire's number.
    pub fn to_wire(self) -> u8 {
        match self {
            Self::Domain => 0,
            Self::Host => 1,
            Self::StartsWith => 2,
            Self::Exact => 3,
            Self::RegularExpression => 4,
            Self::Never => 5,
        }
    }
}

/// How [`Vault::find_logins`](crate::Vault::find_logins) matches.
#[derive(Clone, Debug)]
pub struct MatchOptions {
    /// The match type for a login URI that has none (Bitwarden's default:
    /// [`UriMatch::Domain`]).
    pub default_match: UriMatch,
    /// Whether regex login URIs are honoured (default `false`: they never
    /// match).
    pub allow_regex: bool,
    /// Groups of base domains that count as one for domain matching
    /// (Bitwarden's equivalent domains), e.g.
    /// `[["example.com", "example.net"]]`.
    pub equivalent_domains: Vec<Vec<String>>,
    /// Whether an `https` login URI is kept from `http` pages for domain
    /// and host matching (default `true`).
    pub strict_scheme: bool,
}

impl Default for MatchOptions {
    fn default() -> Self {
        Self {
            default_match: UriMatch::Domain,
            allow_regex: false,
            equivalent_domains: Vec::new(),
            strict_scheme: true,
        }
    }
}

/// The largest compiled regex allowed (bytes): a vault regex can't make a
/// lookup expensive.
const REGEX_SIZE_LIMIT: usize = 1 << 20;

fn parse_web(uri: &str) -> Option<Url> {
    let uri = uri.trim();
    let url = if uri.contains("://") {
        Url::parse(uri).ok()?
    } else {
        Url::parse(&format!("http://{uri}")).ok()?
    };
    matches!(url.scheme(), "http" | "https").then_some(url)
}

/// The base domain of a URL's host: the registrable domain for a name the
/// public suffix list knows, else the host itself (IPs, `localhost`).
fn base_domain(url: &Url) -> Option<String> {
    match url.host()? {
        Host::Ipv4(ip) => Some(ip.to_string()),
        Host::Ipv6(ip) => Some(format!("[{ip}]")),
        Host::Domain(d) => {
            let d = d.trim_end_matches('.');
            if !d.contains('.') {
                return Some(d.to_owned());
            }
            Some(psl::domain_str(d).unwrap_or(d).to_owned())
        }
    }
}

fn host_port(url: &Url) -> Option<String> {
    let host = url.host_str()?.trim_end_matches('.');
    Some(match url.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_owned(),
    })
}

/// Whether the page's scheme is acceptable for the login's.
fn scheme_ok(login: &Url, page: &Url, opts: &MatchOptions) -> bool {
    !opts.strict_scheme || login.scheme() != "https" || page.scheme() == "https"
}

/// Starts-with, at a boundary (see the module docs).
fn starts_with_at_boundary(login_uri: &str, page: &str) -> bool {
    if login_uri.is_empty() {
        return false;
    }
    let Some(rest) = page.strip_prefix(login_uri) else {
        return false;
    };
    rest.is_empty()
        || login_uri.ends_with(['/', '?', '#', '&'])
        || rest.starts_with(['/', '?', '#'])
        || rest.strip_prefix(':').is_some_and(starts_with_port)
}

/// Whether `s` is a port number, then the end or `/`, `?`, `#`.
fn starts_with_port(s: &str) -> bool {
    let digits = s.bytes().take_while(u8::is_ascii_digit).count();
    digits > 0 && (digits == s.len() || s[digits..].starts_with(['/', '?', '#']))
}

/// Whether a page URL carries userinfo (`user:pass@`), by the parser's
/// reading or, for what doesn't parse, by an `@` in its authority.
fn has_userinfo(page: &str) -> bool {
    let page = page.trim();
    if let Ok(url) = Url::parse(page)
        && (!url.username().is_empty() || url.password().is_some())
    {
        return true;
    }
    let after_scheme = page.split_once("://").map_or(page, |(_, rest)| rest);
    let authority = after_scheme
        .split(['/', '\\', '?', '#'])
        .next()
        .unwrap_or_default();
    authority.contains('@')
}

fn equivalent(a: &str, b: &str, opts: &MatchOptions) -> bool {
    a == b
        || opts.equivalent_domains.iter().any(|group| {
            group.iter().any(|d| d.eq_ignore_ascii_case(a))
                && group.iter().any(|d| d.eq_ignore_ascii_case(b))
        })
}

/// Whether `login_uri` (with match type `match_type`, or the default)
/// matches the page URL `page`. A page with userinfo never matches.
pub fn uri_matches(
    login_uri: &str,
    match_type: Option<UriMatch>,
    page: &str,
    opts: &MatchOptions,
) -> bool {
    if has_userinfo(page) {
        return false;
    }
    match match_type.unwrap_or(opts.default_match) {
        UriMatch::Domain => {
            let (Some(l), Some(p)) = (parse_web(login_uri), parse_web(page)) else {
                return false;
            };
            if !scheme_ok(&l, &p, opts) {
                return false;
            }
            match (base_domain(&l), base_domain(&p)) {
                (Some(l), Some(p)) => equivalent(&l, &p, opts),
                _ => false,
            }
        }
        UriMatch::Host => {
            let (Some(l), Some(p)) = (parse_web(login_uri), parse_web(page)) else {
                return false;
            };
            scheme_ok(&l, &p, opts)
                && matches!((host_port(&l), host_port(&p)), (Some(l), Some(p)) if l == p)
        }
        UriMatch::StartsWith => starts_with_at_boundary(login_uri, page),
        UriMatch::Exact => page == login_uri,
        UriMatch::RegularExpression => {
            opts.allow_regex
                && meta::Regex::builder()
                    .configure(
                        meta::Config::new()
                            .nfa_size_limit(Some(REGEX_SIZE_LIMIT))
                            .onepass_size_limit(Some(REGEX_SIZE_LIMIT)),
                    )
                    .syntax(syntax::Config::new().case_insensitive(true))
                    .build(login_uri)
                    .is_ok_and(|re| re.is_match(page))
        }
        UriMatch::Never => false,
    }
}
