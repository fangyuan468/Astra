//! User opt-in that relaxes the private-network SSRF boundary for fake-IP
//! DNS answers.
//!
//! Fake-IP DNS (Clash/mihomo, Surge, sing-box) answers every lookup with an
//! address from `198.18.0.0/15` and routes the connection by hostname. The
//! SSRF guard cannot judge such an answer, so it blocks it by default. When
//! the user opts in through the user-level `[web_fetch]` configuration, the
//! fetch goes to the fake address and the VPN resolves and picks the real
//! destination. Astra cannot observe that destination. A DNS-over-HTTPS lookup
//! screens out hosts whose public answer is private; it is not proof of where
//! the VPN connects, because a host may answer the resolver and the VPN
//! differently.
//!
//! Only `FetchTransport::LocalEnvironment` carries a policy; Server transports
//! never consult it.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use astra_config::runtime_config::{FakeIpMode, RuntimeConfig, WebFetchConfig};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use ipnet::{Ipv4Net, Ipv6Net};
use reqwest::header;

use super::{SsrfBlockReason, is_private_ip};

const DNS_MESSAGE: &str = "application/dns-message";
const DOH_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_DNS_MESSAGE_BYTES: usize = 64 * 1024;
const MAX_CNAME_HOPS: usize = 16;

/// RFC 2544 benchmarking range: never assigned to real hosts, and the range
/// fake-IP implementations draw from.
pub(super) const FAKE_IP_RANGE: Ipv4Net = Ipv4Net::new_assert(Ipv4Addr::new(198, 18, 0, 0), 15);

/// RFC 5180 IPv6 benchmarking range, used by sing-box's documented IPv6
/// fake-IP configuration. Only IPv4 fake answers can be allowed; an answer
/// from this range is reported as unsupported rather than as a LAN address.
pub(super) const FAKE_IPV6_RANGE: Ipv6Net =
    Ipv6Net::new_assert(Ipv6Addr::new(0x2001, 0x0002, 0, 0, 0, 0, 0, 0), 48);

pub(super) fn is_ipv6_fake_candidate(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V6(v6) if FAKE_IPV6_RANGE.contains(&v6))
}

#[derive(Debug)]
pub struct FakeIpPolicy {
    ranges: Vec<Ipv4Net>,
    resolvers: Vec<url::Url>,
}

impl FakeIpPolicy {
    /// Build the policy selected by configuration. `Ok(None)` means the user
    /// has not opted in.
    pub fn from_config(config: &WebFetchConfig) -> Result<Option<Self>, String> {
        if config.fake_ip == FakeIpMode::Block {
            return Ok(None);
        }
        let ranges = if config.fake_ip_ranges.is_empty() {
            vec![FAKE_IP_RANGE]
        } else {
            config
                .fake_ip_ranges
                .iter()
                .map(|raw| parse_fake_ip_range(raw))
                .collect::<Result<_, _>>()?
        };
        if config.doh_resolvers.is_empty() {
            return Err(
                "web_fetch.fake_ip = \"allow_doh_screened\" requires at least one doh_resolvers entry"
                    .into(),
            );
        }
        let resolvers = config
            .doh_resolvers
            .iter()
            .enumerate()
            .map(|(index, raw)| parse_doh_resolver(index, raw))
            .collect::<Result<_, _>>()?;
        Ok(Some(Self { ranges, resolvers }))
    }

    #[cfg(test)]
    pub(super) fn for_test(resolvers: Vec<url::Url>) -> Self {
        Self {
            ranges: vec![FAKE_IP_RANGE],
            resolvers,
        }
    }

    pub(super) fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.ranges.iter().any(|range| range.contains(&v4)),
            IpAddr::V6(_) => false,
        }
    }

    /// Pass `host` only when a configured resolver gives complete, consistent
    /// answers for both address families and no reported address is in an
    /// Astra-blocked range. Fails closed when no resolver does. Passing does not bind the
    /// VPN's destination; see the module documentation.
    ///
    /// A private address blocks the host even when it came from a truncated
    /// response or the other family's query failed: a later resolver must not
    /// be able to outvote evidence that has already been seen.
    pub(super) async fn screen(&self, host: &str) -> Result<(), SsrfBlockReason> {
        let mut name = Name::from_ascii(host).map_err(|_| SsrfBlockReason::FakeIpNoDohAnswer)?;
        name.set_fqdn(true);
        let mut failures = Vec::new();
        let mut empty_answers = 0;
        for (index, resolver) in self.resolvers.iter().enumerate() {
            let (v4, v6) = resolve_via_doh(resolver, &name).await;
            let real: Vec<IpAddr> = v4.addrs.iter().chain(&v6.addrs).copied().collect();
            if real.iter().any(|ip| is_private_ip(*ip)) {
                return Err(SsrfBlockReason::FakeIpRealAddressPrivate(real));
            }
            let failure = match (&v4.status, &v6.status) {
                (AnswerStatus::Failed(error), _) | (_, AnswerStatus::Failed(error)) => {
                    error.clone()
                }
                // NXDOMAIN says the name has no records of any type.
                (AnswerStatus::NxDomain, _) | (_, AnswerStatus::NxDomain) if !real.is_empty() => {
                    "contradictory answers: NXDOMAIN for one address family, records for the other"
                        .to_string()
                }
                _ if real.is_empty() => {
                    empty_answers += 1;
                    "no address records".to_string()
                }
                _ => return Ok(()),
            };
            failures.push(format!("{}: {failure}", resolver_label(index, resolver)));
        }
        if empty_answers == self.resolvers.len() {
            Err(SsrfBlockReason::FakeIpNoDohAnswer)
        } else {
            Err(SsrfBlockReason::FakeIpDohUnavailable(failures.join("; ")))
        }
    }
}

/// The policy from the user's runtime configuration, for Edge/CLI owners.
/// Invalid configuration is reported and leaves the default block in place.
pub fn configured_fake_ip_policy() -> Result<Option<Arc<FakeIpPolicy>>, String> {
    FakeIpPolicy::from_config(&RuntimeConfig::cached().web_fetch).map(|policy| policy.map(Arc::new))
}

fn parse_fake_ip_range(raw: &str) -> Result<Ipv4Net, String> {
    let range = raw
        .trim()
        .parse::<Ipv4Net>()
        .map_err(|_| "invalid web_fetch.fake_ip_ranges entry".to_string())?
        .trunc();
    if !FAKE_IP_RANGE.contains(&range) {
        return Err(format!(
            "web_fetch.fake_ip_ranges entry must lie within {FAKE_IP_RANGE}"
        ));
    }
    Ok(range)
}

/// Resolver URLs may carry account identifiers in their path or query, so
/// diagnostics name a resolver only by position and host.
fn resolver_label(index: usize, resolver: &url::Url) -> String {
    format!(
        "doh_resolvers[{index}] ({})",
        resolver.host_str().unwrap_or("?")
    )
}

fn parse_doh_resolver(index: usize, raw: &str) -> Result<url::Url, String> {
    let entry = format!("web_fetch.doh_resolvers[{index}]");
    let url = url::Url::parse(raw.trim()).map_err(|e| format!("invalid {entry}: {e}"))?;
    if url.scheme() != "https" || url.host_str().is_none() {
        return Err(format!("{entry} must be an https:// URL"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(format!("{entry} must not embed credentials"));
    }
    Ok(url)
}

/// One address family's answer from one resolver.
struct FamilyAnswer {
    /// Addresses the response carried, even when it is unusable as a whole: a
    /// private address in a truncated response is still evidence.
    addrs: Vec<IpAddr>,
    status: AnswerStatus,
}

enum AnswerStatus {
    Complete,
    NxDomain,
    Failed(String),
}

impl FamilyAnswer {
    fn failed(error: String) -> Self {
        Self {
            addrs: Vec::new(),
            status: AnswerStatus::Failed(error),
        }
    }
}

/// A and AAAA answers from one resolver, kept apart so a failure in one
/// family does not discard what the other reported.
async fn resolve_via_doh(resolver: &url::Url, name: &Name) -> (FamilyAnswer, FamilyAnswer) {
    let client = match astra_core::net::client_builder_for_target(resolver.as_str())
        .timeout(DOH_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            let error = format!("client init failed: {}", transport_failure(error));
            return (
                FamilyAnswer::failed(error.clone()),
                FamilyAnswer::failed(error),
            );
        }
    };
    let (v4, v6) = futures::join!(
        bounded_query(&client, resolver, name, RecordType::A),
        bounded_query(&client, resolver, name, RecordType::AAAA)
    );
    (v4, v6)
}

async fn bounded_query(
    client: &reqwest::Client,
    resolver: &url::Url,
    name: &Name,
    record_type: RecordType,
) -> FamilyAnswer {
    match tokio::time::timeout(DOH_TIMEOUT, query(client, resolver, name, record_type)).await {
        Ok(answer) => answer,
        Err(_) => FamilyAnswer::failed(format!("{record_type} query timed out")),
    }
}

async fn query(
    client: &reqwest::Client,
    resolver: &url::Url,
    name: &Name,
    record_type: RecordType,
) -> FamilyAnswer {
    let mut current = name.clone();
    let mut visited = vec![current.clone()];
    loop {
        let answer = match query_message(client, resolver, &current, record_type).await {
            Ok(answer) => answer,
            Err(error) => return FamilyAnswer::failed(error),
        };
        // Retain private evidence even if this response is otherwise invalid.
        let addrs: Vec<IpAddr> = answer
            .answers
            .iter()
            .filter_map(|record| match &record.data {
                RData::A(a) => Some(IpAddr::V4(a.0)),
                RData::AAAA(a) => Some(IpAddr::V6(a.0)),
                _ => None,
            })
            .collect();
        let failed = |error: String| FamilyAnswer {
            addrs: addrs.clone(),
            status: AnswerStatus::Failed(error),
        };
        if answer.metadata.message_type != MessageType::Response
            || answer.metadata.op_code != OpCode::Query
            || answer.metadata.id != 0
            || answer.queries.len() != 1
            || answer.queries[0].name() != &current
            || answer.queries[0].query_type() != record_type
            || answer.queries[0].query_class() != DNSClass::IN
        {
            return failed("DNS response does not match the query".into());
        }
        if addrs.iter().any(|ip| is_private_ip(*ip)) {
            return FamilyAnswer {
                addrs,
                status: AnswerStatus::Complete,
            };
        }
        if answer.metadata.truncation {
            return failed(format!("truncated {record_type} response"));
        }
        match answer.metadata.response_code {
            ResponseCode::NoError => {}
            ResponseCode::NXDomain => {
                return FamilyAnswer {
                    addrs,
                    status: AnswerStatus::NxDomain,
                };
            }
            code => return failed(format!("DNS response code {code}")),
        }

        let mut terminal = current.clone();
        let mut chain = vec![terminal.clone()];
        loop {
            let mut targets = answer.answers.iter().filter_map(|record| {
                if record.name == terminal
                    && record.dns_class == DNSClass::IN
                    && let RData::CNAME(target) = &record.data
                {
                    return Some(target.0.clone());
                }
                None
            });
            let Some(target) = targets.next() else { break };
            if targets.any(|other| other != target)
                || visited.contains(&target)
                || visited.len() >= MAX_CNAME_HOPS
            {
                return failed("invalid or cyclic CNAME chain".into());
            }
            visited.push(target.clone());
            chain.push(target.clone());
            terminal = target;
        }
        for record in &answer.answers {
            match &record.data {
                RData::A(_) | RData::AAAA(_) => {
                    if record.name != terminal
                        || record.dns_class != DNSClass::IN
                        || record.record_type() != record_type
                    {
                        return failed("unrelated DNS address record".into());
                    }
                }
                RData::CNAME(_)
                    if record.dns_class != DNSClass::IN
                        || !chain[..chain.len() - 1].contains(&record.name) =>
                {
                    return failed("unrelated DNS CNAME record".into());
                }
                _ => {}
            }
        }
        if !addrs.is_empty() {
            return FamilyAnswer {
                addrs,
                status: AnswerStatus::Complete,
            };
        }
        let has_soa = answer.authorities.iter().any(|r| {
            r.dns_class == DNSClass::IN
                && matches!(r.data, RData::SOA(_))
                && r.name.zone_of(&terminal)
        });
        let referral = answer
            .authorities
            .iter()
            .any(|r| matches!(r.data, RData::NS(_)));
        if referral && !has_soa {
            return failed("DNS response is a referral".into());
        }
        if chain.len() == 1 || has_soa {
            return FamilyAnswer {
                addrs,
                status: AnswerStatus::Complete,
            };
        }
        current = terminal;
    }
}

async fn query_message(
    client: &reqwest::Client,
    resolver: &url::Url,
    name: &Name,
    record_type: RecordType,
) -> Result<Message, String> {
    // RFC 8484 recommends ID 0 so responses stay cacheable.
    let mut request = Message::new(0, MessageType::Query, OpCode::Query);
    request.metadata.recursion_desired = true;
    request.add_query(Query::query(name.clone(), record_type));
    let body = request.to_vec().map_err(|e| e.to_string())?;
    let mut response = client
        .post(resolver.clone())
        .header(header::CONTENT_TYPE, DNS_MESSAGE)
        .header(header::ACCEPT, DNS_MESSAGE)
        .body(body)
        .send()
        .await
        .map_err(transport_failure)?;
    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status()));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(transport_failure)? {
        if bytes.len() + chunk.len() > MAX_DNS_MESSAGE_BYTES {
            return Err("DNS response too large".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    Message::from_vec(&bytes).map_err(|e| format!("malformed DNS response: {e}"))
}

/// Keep the underlying cause (for example "connection reset by peer"):
/// reqwest's own message alone does not tell the user why DoH failed.
fn transport_failure(error: reqwest::Error) -> String {
    let error = error.without_url();
    let mut message = error.to_string();
    let mut source = std::error::Error::source(&error);
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    message
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use hickory_proto::rr::Record;
    use hickory_proto::rr::rdata::{A, AAAA};
    use wiremock::matchers::{header, method};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    use super::*;
    use crate::web_fetch::{
        FetchError, FetchNetwork, resolve_and_validate_host, validate_resolved_addrs,
    };

    /// How a DoH fixture misanswers queries for one record type.
    #[derive(Clone, Copy, Debug)]
    enum Degrade {
        Http503,
        /// TC=1, still carrying the configured records.
        Truncated,
        /// NXDOMAIN with no records, while the other type answers normally.
        NxDomain,
    }

    /// A DoH endpoint answering A and AAAA queries from fixed record sets.
    struct DohAnswers {
        code: ResponseCode,
        v4: Vec<Ipv4Addr>,
        v6: Vec<Ipv6Addr>,
        degraded: Option<(RecordType, Degrade)>,
    }

    impl Respond for DohAnswers {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            let query = Message::from_vec(&request.body).expect("DNS query body");
            let question = query.queries[0].clone();
            let degrade = self
                .degraded
                .filter(|(record_type, _)| *record_type == question.query_type())
                .map(|(_, degrade)| degrade);
            let mut response = Message::response(query.metadata.id, OpCode::Query);
            response.add_query(question.clone());
            response.metadata.response_code = self.code;
            match degrade {
                Some(Degrade::Http503) => return ResponseTemplate::new(503),
                Some(Degrade::Truncated) => response.metadata.truncation = true,
                Some(Degrade::NxDomain) => response.metadata.response_code = ResponseCode::NXDomain,
                None => {}
            }
            let name = question.name().clone();
            let records: Vec<Record> = match (degrade, question.query_type()) {
                (Some(Degrade::NxDomain), _) => Vec::new(),
                (_, RecordType::A) => self
                    .v4
                    .iter()
                    .map(|ip| Record::from_rdata(name.clone(), 60, RData::A(A(*ip))))
                    .collect(),
                (_, RecordType::AAAA) => self
                    .v6
                    .iter()
                    .map(|ip| Record::from_rdata(name.clone(), 60, RData::AAAA(AAAA(*ip))))
                    .collect(),
                _ => Vec::new(),
            };
            response.add_answers(records);
            ResponseTemplate::new(200)
                .insert_header("content-type", DNS_MESSAGE)
                .set_body_bytes(response.to_vec().expect("encode DNS response"))
        }
    }

    async fn doh(code: ResponseCode, v4: &[&str], v6: &[&str]) -> MockServer {
        doh_degraded(code, v4, v6, None).await
    }

    async fn doh_degraded(
        code: ResponseCode,
        v4: &[&str],
        v6: &[&str],
        degraded: Option<(RecordType, Degrade)>,
    ) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(header("content-type", DNS_MESSAGE))
            .respond_with(DohAnswers {
                code,
                v4: v4.iter().map(|ip| ip.parse().unwrap()).collect(),
                v6: v6.iter().map(|ip| ip.parse().unwrap()).collect(),
                degraded,
            })
            .mount(&server)
            .await;
        server
    }

    fn policy(servers: &[&MockServer]) -> FakeIpPolicy {
        FakeIpPolicy::for_test(
            servers
                .iter()
                .map(|server| url::Url::parse(&format!("{}/dns-query", server.uri())).unwrap())
                .collect(),
        )
    }

    fn addrs(ips: &[&str]) -> Vec<SocketAddr> {
        ips.iter()
            .map(|ip| SocketAddr::new(ip.parse().unwrap(), 443))
            .collect()
    }

    fn reason(error: FetchError) -> SsrfBlockReason {
        match error {
            FetchError::SsrfBlocked(block) => block.reason,
            other => panic!("expected an SSRF block, got {other:?}"),
        }
    }

    fn config(mode: FakeIpMode, ranges: &[&str], resolvers: &[&str]) -> WebFetchConfig {
        WebFetchConfig {
            fake_ip: mode,
            fake_ip_ranges: ranges.iter().map(ToString::to_string).collect(),
            doh_resolvers: resolvers.iter().map(ToString::to_string).collect(),
        }
    }

    #[derive(Clone, Copy)]
    enum ChallengedAnswer {
        WrongQuestion,
        WrongId,
        WrongType,
        WrongClass,
        WrongRecordClass,
        WrongQuestionPrivate,
        UnrelatedAddress,
        Alias,
        AliasPrivate,
        AliasPrivateV6,
        BundledAlias,
        AliasSoa,
        UnrelatedSoaReferral,
        AliasLoop,
        Referral,
    }

    impl Respond for ChallengedAnswer {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            use hickory_proto::rr::rdata::{CNAME, NS, SOA};
            let request = Message::from_vec(&request.body).unwrap();
            let question = &request.queries[0];
            let mut response = Message::response(
                if matches!(self, Self::WrongId) {
                    42
                } else {
                    request.metadata.id
                },
                OpCode::Query,
            );
            let unrelated = Name::from_ascii("unrelated.example.").unwrap();
            let alias = Name::from_ascii("alias.example.").unwrap();
            let mut echoed = question.clone();
            if matches!(self, Self::WrongQuestion | Self::WrongQuestionPrivate) {
                echoed = Query::query(unrelated.clone(), question.query_type());
            }
            if matches!(self, Self::WrongType) {
                echoed = Query::query(question.name().clone(), RecordType::MX);
            }
            if matches!(self, Self::WrongClass) {
                echoed.set_query_class(DNSClass::CH);
            }
            response.add_query(echoed);
            match self {
                Self::Alias | Self::AliasPrivate | Self::AliasPrivateV6 | Self::AliasLoop
                    if question.name() != &alias =>
                {
                    response.add_answer(Record::from_rdata(
                        question.name().clone(),
                        60,
                        RData::CNAME(CNAME(alias)),
                    ));
                }
                Self::AliasLoop => {
                    response.add_answer(Record::from_rdata(
                        alias,
                        60,
                        RData::CNAME(CNAME(Name::from_ascii("target.example.").unwrap())),
                    ));
                }
                Self::Referral => {
                    response.add_authority(Record::from_rdata(
                        question.name().clone(),
                        60,
                        RData::NS(NS(alias)),
                    ));
                }
                Self::BundledAlias if question.query_type() == RecordType::A => {
                    let terminal = Name::from_ascii("END.example.").unwrap();
                    response.add_answer(Record::from_rdata(
                        terminal.clone(),
                        60,
                        RData::A(A("8.8.8.8".parse().unwrap())),
                    ));
                    response.add_answer(Record::from_rdata(
                        alias.clone(),
                        60,
                        RData::CNAME(CNAME(terminal)),
                    ));
                    response.add_answer(Record::from_rdata(
                        question.name().clone(),
                        60,
                        RData::CNAME(CNAME(Name::from_ascii("ALIAS.example.").unwrap())),
                    ));
                }
                Self::AliasSoa | Self::UnrelatedSoaReferral
                    if question.query_type() == RecordType::AAAA =>
                {
                    response.add_answer(Record::from_rdata(
                        question.name().clone(),
                        60,
                        RData::CNAME(CNAME(alias.clone())),
                    ));
                    let zone = if matches!(self, Self::AliasSoa) {
                        Name::from_ascii("example.").unwrap()
                    } else {
                        unrelated.clone()
                    };
                    response.add_authority(Record::from_rdata(
                        zone,
                        60,
                        RData::SOA(SOA::new(alias.clone(), alias.clone(), 1, 1, 1, 1, 1)),
                    ));
                    if matches!(self, Self::UnrelatedSoaReferral) {
                        response.add_authority(Record::from_rdata(
                            unrelated.clone(),
                            60,
                            RData::NS(NS(alias)),
                        ));
                    }
                }
                Self::AliasPrivateV6 if question.query_type() == RecordType::AAAA => {
                    response.add_answer(Record::from_rdata(
                        question.name().clone(),
                        60,
                        RData::AAAA(AAAA("::1".parse().unwrap())),
                    ));
                }
                _ if question.query_type() == RecordType::A => {
                    let owner = if matches!(self, Self::UnrelatedAddress) {
                        unrelated
                    } else {
                        question.name().clone()
                    };
                    let ip = if matches!(self, Self::AliasPrivate | Self::WrongQuestionPrivate) {
                        "127.0.0.1"
                    } else {
                        "8.8.8.8"
                    };
                    let mut record =
                        Record::from_rdata(owner, 60, RData::A(A(ip.parse().unwrap())));
                    if matches!(self, Self::WrongRecordClass) {
                        record.dns_class = DNSClass::CH;
                    }
                    response.add_answer(record);
                }
                _ => {}
            }
            ResponseTemplate::new(200).set_body_bytes(response.to_vec().unwrap())
        }
    }

    #[tokio::test]
    async fn screening_checks_question_and_address_ownership() {
        for answer in [
            ChallengedAnswer::WrongQuestion,
            ChallengedAnswer::WrongId,
            ChallengedAnswer::WrongType,
            ChallengedAnswer::WrongClass,
            ChallengedAnswer::WrongRecordClass,
            ChallengedAnswer::UnrelatedAddress,
            ChallengedAnswer::UnrelatedSoaReferral,
            ChallengedAnswer::AliasLoop,
            ChallengedAnswer::Referral,
        ] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(answer)
                .mount(&server)
                .await;
            assert!(policy(&[&server]).screen("target.example").await.is_err());
        }
    }

    #[tokio::test]
    async fn screening_follows_aliases_and_blocks_private_terminal_addresses() {
        for (answer, accepted) in [
            (ChallengedAnswer::Alias, true),
            (ChallengedAnswer::AliasPrivate, false),
            (ChallengedAnswer::AliasPrivateV6, false),
            (ChallengedAnswer::BundledAlias, true),
            (ChallengedAnswer::AliasSoa, true),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(answer)
                .mount(&server)
                .await;
            let result = policy(&[&server]).screen("target.example").await;
            assert_eq!(result.is_ok(), accepted, "{result:?}");
        }
    }

    #[tokio::test]
    async fn invalid_policy_reason_reaches_the_local_tool_result() {
        let selection = FakeIpPolicy::from_config(&config(FakeIpMode::AllowDohScreened, &[], &[]))
            .map(|policy| policy.map(Arc::new));
        let network = FetchNetwork::local_environment(selection);
        let blocked = validate_resolved_addrs("target.example", addrs(&["198.18.0.1"]), None)
            .await
            .unwrap_err();
        let result = crate::web_fetch::render_fetch_result(Err(blocked), &network);
        assert!(result.is_error);
        assert!(
            result
                .output
                .contains("requires at least one doh_resolvers"),
            "{}",
            result.output
        );
        assert!(!result.output.contains("The user can choose to relax"));
    }

    #[tokio::test]
    async fn private_evidence_in_a_mismatched_answer_cannot_be_overruled() {
        let suspect = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ChallengedAnswer::WrongQuestionPrivate)
            .mount(&suspect)
            .await;
        let public = doh(ResponseCode::NoError, &["8.8.8.8"], &[]).await;
        let result = policy(&[&suspect, &public]).screen("target.example").await;
        assert!(matches!(
            result,
            Err(SsrfBlockReason::FakeIpRealAddressPrivate(_))
        ));
        assert!(public.received_requests().await.unwrap().is_empty());
    }

    #[test]
    fn configuration_is_opt_in_and_validated() {
        let doh = FakeIpMode::AllowDohScreened;
        let resolver = ["https://1.12.12.12/dns-query"];
        assert!(
            FakeIpPolicy::from_config(&config(FakeIpMode::Block, &[], &resolver))
                .unwrap()
                .is_none()
        );
        let default = FakeIpPolicy::from_config(&config(doh, &[], &resolver))
            .unwrap()
            .unwrap();
        assert!(default.contains("198.19.255.1".parse().unwrap()));
        let narrow = FakeIpPolicy::from_config(&config(doh, &["198.18.0.1/16"], &resolver))
            .unwrap()
            .unwrap();
        assert!(narrow.contains("198.18.3.4".parse().unwrap()));
        assert!(!narrow.contains("198.19.0.1".parse().unwrap()));

        for (ranges, resolvers, expected) in [
            (&[][..], &[][..], "requires at least one doh_resolvers"),
            (
                &[][..],
                &["http://1.12.12.12/dns-query"][..],
                "must be an https:// URL",
            ),
            (
                &[][..],
                &["https://user:secret@doh.example/dns-query"][..],
                "doh_resolvers[0] must not embed credentials",
            ),
            (
                &["10.0.0.0/8"][..],
                &resolver[..],
                "must lie within 198.18.0.0/15",
            ),
            (
                &["198.0.0.0/8"][..],
                &resolver[..],
                "must lie within 198.18.0.0/15",
            ),
            (
                &["fc00::/7"][..],
                &resolver[..],
                "invalid web_fetch.fake_ip_ranges",
            ),
        ] {
            let error = FakeIpPolicy::from_config(&config(doh, ranges, resolvers)).unwrap_err();
            assert!(error.contains(expected), "{error}");
            assert!(!error.contains("secret"), "{error}");
        }
    }

    #[tokio::test]
    async fn fake_ip_answer_is_blocked_with_user_opt_in_hint_by_default() {
        let error = validate_resolved_addrs("www.bing.com", addrs(&["198.18.5.51"]), None)
            .await
            .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("198.18.5.51"), "{message}");
        assert!(
            message.contains("fake_ip = \"allow_doh_screened\""),
            "{message}"
        );
        assert!(
            message.contains("do not change their configuration"),
            "{message}"
        );
        assert_eq!(reason(error), SsrfBlockReason::FakeIpNotEnabled);
    }

    #[tokio::test]
    async fn real_private_answer_never_suggests_the_opt_in() {
        for answer in [&["10.0.0.5"][..], &["198.18.0.9", "127.0.0.1"][..]] {
            let error = validate_resolved_addrs("intranet.example", addrs(answer), None)
                .await
                .unwrap_err();
            assert!(!error.to_string().contains("fake_ip"));
            assert_eq!(reason(error), SsrfBlockReason::PrivateAddress);
        }
    }

    #[tokio::test]
    async fn screened_host_connects_through_the_fake_address() {
        let server = doh(ResponseCode::NoError, &["140.82.113.4"], &[]).await;
        let fake = addrs(&["198.18.0.23"]);
        let admitted =
            validate_resolved_addrs("github.com", fake.clone(), Some(&policy(&[&server])))
                .await
                .unwrap();
        assert_eq!(
            admitted, fake,
            "the pinned connection must use the VPN's fake address"
        );
    }

    /// Documents the accepted limitation: screening sees only the DoH answer.
    /// A host that gives DoH a public address and the VPN's DNS a private one
    /// is admitted, and the connection goes to the fake address, which the VPN
    /// then routes to wherever its own lookup pointed.
    #[tokio::test]
    async fn screening_cannot_bind_the_destination_the_vpn_picks() {
        let doh_view = doh(ResponseCode::NoError, &["93.184.216.34"], &[]).await;
        let vpn_view = "127.0.0.1".parse::<IpAddr>().unwrap();
        let fake = addrs(&["198.18.0.7"]);
        let admitted =
            validate_resolved_addrs("rebind.example", fake.clone(), Some(&policy(&[&doh_view])))
                .await
                .expect("screening passes on the DoH view alone");
        assert_eq!(admitted, fake);
        assert!(
            admitted.iter().all(|addr| addr.ip() != vpn_view),
            "Astra never sees the VPN's destination, so it cannot reject it"
        );
    }

    #[tokio::test]
    async fn doh_reporting_any_private_real_address_is_blocked() {
        for (v4, v6) in [
            (&["0.0.0.1"][..], &[][..]),
            (&["127.0.0.1"][..], &[][..]),
            (&["93.184.216.34", "10.1.2.3"][..], &[][..]),
            (&["93.184.216.34"][..], &["::1"][..]),
            // A fake-range answer from DoH is not a real address either.
            (&["198.18.0.1"][..], &[][..]),
            (&["93.184.216.34"][..], &["2001:2::1"][..]),
        ] {
            let server = doh(ResponseCode::NoError, v4, v6).await;
            let error = validate_resolved_addrs(
                "evil.example",
                addrs(&["198.18.0.7"]),
                Some(&policy(&[&server])),
            )
            .await
            .unwrap_err();
            assert!(
                matches!(reason(error), SsrfBlockReason::FakeIpRealAddressPrivate(_)),
                "{v4:?} {v6:?}"
            );
        }
    }

    #[tokio::test]
    async fn missing_doh_answer_is_blocked() {
        for code in [ResponseCode::NoError, ResponseCode::NXDomain] {
            let server = doh(code, &[], &[]).await;
            let error = validate_resolved_addrs(
                "gone.example",
                addrs(&["198.18.0.7"]),
                Some(&policy(&[&server])),
            )
            .await
            .unwrap_err();
            assert_eq!(reason(error), SsrfBlockReason::FakeIpNoDohAnswer);
        }
    }

    #[tokio::test]
    async fn unreachable_doh_fails_closed_and_later_resolvers_are_tried() {
        let broken = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&broken)
            .await;
        let error = validate_resolved_addrs(
            "github.com",
            addrs(&["198.18.0.23"]),
            Some(&policy(&[&broken])),
        )
        .await
        .unwrap_err();
        let SsrfBlockReason::FakeIpDohUnavailable(detail) = reason(error) else {
            panic!("an unreachable resolver must fail closed");
        };
        assert!(detail.contains("HTTP 503"), "{detail}");
        assert!(detail.contains("doh_resolvers[0] (127.0.0.1)"), "{detail}");

        let working = doh(ResponseCode::NoError, &["140.82.113.4"], &[]).await;
        validate_resolved_addrs(
            "github.com",
            addrs(&["198.18.0.23"]),
            Some(&policy(&[&broken, &working])),
        )
        .await
        .expect("the next configured resolver answers");

        let empty = doh(ResponseCode::NoError, &[], &[]).await;
        validate_resolved_addrs(
            "github.com",
            addrs(&["198.18.0.23"]),
            Some(&policy(&[&empty, &working])),
        )
        .await
        .expect("an empty answer does not prevent trying the next resolver");
    }

    #[tokio::test]
    async fn private_answer_in_one_family_survives_a_failure_in_the_other() {
        let public = doh(ResponseCode::NoError, &["140.82.113.4"], &[]).await;
        for (failing, v4, v6) in [
            (RecordType::AAAA, &["127.0.0.1"][..], &[][..]),
            (RecordType::A, &[][..], &["::1"][..]),
        ] {
            let partial = doh_degraded(
                ResponseCode::NoError,
                v4,
                v6,
                Some((failing, Degrade::Http503)),
            )
            .await;
            let error = validate_resolved_addrs(
                "evil.example",
                addrs(&["198.18.0.7"]),
                Some(&policy(&[&partial, &public])),
            )
            .await
            .unwrap_err();
            assert!(
                matches!(reason(error), SsrfBlockReason::FakeIpRealAddressPrivate(_)),
                "{failing:?} failure must not let the next resolver admit the host"
            );
        }
        // A partial public answer is not proof either: try the next resolver.
        let partial = doh_degraded(
            ResponseCode::NoError,
            &["140.82.113.4"],
            &[],
            Some((RecordType::AAAA, Degrade::Http503)),
        )
        .await;
        let error = validate_resolved_addrs(
            "github.com",
            addrs(&["198.18.0.23"]),
            Some(&policy(&[&partial])),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            reason(error),
            SsrfBlockReason::FakeIpDohUnavailable(_)
        ));
    }

    #[tokio::test]
    async fn incomplete_or_contradictory_doh_answers_are_not_trusted() {
        let public = doh(ResponseCode::NoError, &["140.82.113.4"], &[]).await;
        for (degraded, v4, v6, expected) in [
            (
                (RecordType::A, Degrade::Truncated),
                &["140.82.113.4"][..],
                &[][..],
                "truncated A response",
            ),
            (
                (RecordType::AAAA, Degrade::Truncated),
                &["140.82.113.4"][..],
                &["2606:50c0:8000::154"][..],
                "truncated AAAA response",
            ),
            (
                (RecordType::A, Degrade::NxDomain),
                &[][..],
                &["2606:50c0:8000::154"][..],
                "contradictory answers",
            ),
            (
                (RecordType::AAAA, Degrade::NxDomain),
                &["140.82.113.4"][..],
                &[][..],
                "contradictory answers",
            ),
        ] {
            let suspect = doh_degraded(ResponseCode::NoError, v4, v6, Some(degraded)).await;
            let error = validate_resolved_addrs(
                "github.com",
                addrs(&["198.18.0.23"]),
                Some(&policy(&[&suspect])),
            )
            .await
            .unwrap_err();
            let SsrfBlockReason::FakeIpDohUnavailable(detail) = reason(error) else {
                panic!("{degraded:?} must fail closed");
            };
            assert!(detail.contains(expected), "{degraded:?}: {detail}");
            validate_resolved_addrs(
                "github.com",
                addrs(&["198.18.0.23"]),
                Some(&policy(&[&suspect, &public])),
            )
            .await
            .unwrap_or_else(|error| panic!("{degraded:?} must fall back: {error:?}"));
        }

        // What a truncated response did carry still counts as evidence.
        let truncated = doh_degraded(
            ResponseCode::NoError,
            &["140.82.113.4", "127.0.0.1"],
            &[],
            Some((RecordType::A, Degrade::Truncated)),
        )
        .await;
        let error = validate_resolved_addrs(
            "evil.example",
            addrs(&["198.18.0.7"]),
            Some(&policy(&[&truncated, &public])),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            reason(error),
            SsrfBlockReason::FakeIpRealAddressPrivate(_)
        ));
    }

    #[tokio::test]
    async fn resolver_diagnostics_omit_url_path_and_query() {
        let broken = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&broken)
            .await;
        let resolver =
            url::Url::parse(&format!("{}/profile-secret?token=secret", broken.uri())).unwrap();
        let error = validate_resolved_addrs(
            "github.com",
            addrs(&["198.18.0.23"]),
            Some(&FakeIpPolicy::for_test(vec![resolver])),
        )
        .await
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("doh_resolvers[0]"), "{message}");
        assert!(!message.contains("secret"), "{message}");
    }

    #[tokio::test]
    async fn unsupported_fake_ip_answers_are_rejected_without_consulting_doh() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let opted_in = policy(&[&server]);
        for answer in [
            // sing-box's documented IPv6 fake-IP range
            &["2001:2::7"][..],
            &["198.18.0.7", "2001:2::7"][..],
            // IPv4 fake address next to a real public IPv6 address
            &["198.18.0.7", "2606:4700::1111"][..],
        ] {
            for fake_ip in [None, Some(&opted_in)] {
                let error = validate_resolved_addrs("dual.example", addrs(answer), fake_ip)
                    .await
                    .unwrap_err();
                let message = error.to_string();
                assert!(message.contains("not supported"), "{message}");
                assert!(
                    message.contains("do not change their configuration"),
                    "{message}"
                );
                assert_eq!(
                    reason(error),
                    SsrfBlockReason::FakeIpUnsupportedAnswer,
                    "{answer:?}"
                );
            }
        }
        // A real LAN address is never described as fake-IP.
        let error = validate_resolved_addrs("lan.example", addrs(&["fd00::5"]), Some(&opted_in))
            .await
            .unwrap_err();
        assert_eq!(reason(error), SsrfBlockReason::PrivateAddress);
    }

    #[tokio::test]
    async fn doh_is_consulted_only_when_every_answer_is_fake() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let policy = policy(&[&server]);
        let public = addrs(&["140.82.113.4"]);
        assert_eq!(
            validate_resolved_addrs("github.com", public.clone(), Some(&policy))
                .await
                .unwrap(),
            public
        );
        let error = validate_resolved_addrs(
            "mixed.example",
            addrs(&["198.18.0.7", "10.0.0.1"]),
            Some(&policy),
        )
        .await
        .unwrap_err();
        assert_eq!(reason(error), SsrfBlockReason::PrivateAddress);
        // A literal fake address has no hostname to screen.
        let error = resolve_and_validate_host("http://198.18.0.5/", Some(&policy))
            .await
            .unwrap_err();
        assert_eq!(reason(error), SsrfBlockReason::PrivateAddress);
    }

    #[test]
    fn only_the_local_environment_can_carry_the_opt_in() {
        assert!(matches!(FetchNetwork::direct_pinned().fake_ip, Ok(None)));
        assert!(matches!(FetchNetwork::default().fake_ip, Ok(None)));
        let local =
            FetchNetwork::local_environment(Ok(Some(Arc::new(FakeIpPolicy::for_test(Vec::new())))));
        assert!(matches!(local.fake_ip, Ok(Some(_))));
    }
}
