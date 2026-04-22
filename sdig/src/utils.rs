use dns_rs::dns::message::DnsMessage;
use dns_rs::dns::rdata::RData;
use std::net::{Ipv4Addr, Ipv6Addr};

// --------------------------------------
// conversion methods
// --------------------------------------
#[allow(dead_code)] // TODO Remove this
pub fn to_ipv4_string(rdata: &RData) -> Option<String> {
    match rdata {
        RData::A(addr) => Some(format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])),
        _ => None,
    }
}

#[allow(dead_code)] // TODO Remove this
pub fn domain_name(rdata: &RData) -> Option<&str> {
    match rdata {
        RData::CNAME(name) | RData::NS(name) | RData::PTR(name) => Some(name.as_str()),
        _ => None,
    }
}

#[allow(dead_code)] // TODO Remove this
fn format_rdata(rdata: &RData) -> String {
    match rdata {
        RData::A(addr) => Ipv4Addr::from(*addr).to_string(),
        RData::AAAA(addr) => Ipv6Addr::from(*addr).to_string(),
        RData::CNAME(name) | RData::NS(name) | RData::PTR(name) => name.clone(),
        RData::MX {
            preference,
            exchange,
        } => format!("{} {}", preference, exchange),
        RData::TXT(texts) => texts
            .iter()
            .map(|t| String::from_utf8_lossy(t).into_owned())
            .collect::<Vec<_>>()
            .join(" "),
        RData::SOA {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } => format!(
            "{} {} {} {} {} {} {}",
            mname, rname, serial, refresh, retry, expire, minimum
        ),
        RData::Unknown(data) => format!("{:x?}", data),
    }
}

pub fn format_request(msg: &DnsMessage) -> String {
    let mut out = String::new();

    out.push_str(&format!(";; id: {}\n", msg.header.id));
    out.push_str(&format!(";; opcode: {}\n", msg.header.opcode));
    out.push_str(&format!(";; recursive: {}\n", msg.header.rd));

    if let Some(q) = msg.questions.first() {
        out.push_str(&format!(";; query: {} ({:?})\n", q.qname, q.qtype));
    }

    out
}
