use std::net::{Ipv4Addr, Ipv6Addr};

use dns_rs::dns::message::DnsMessage;
use dns_rs::dns::rdata::RData;
use dns_rs::dns::resource_record::ResourceRecord;

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

pub fn format_resource_record(rr: &ResourceRecord) -> String {
    let mut out = String::new();

    out.push_str(&format!("name: {}\n", rr.name));
    out.push_str(&format!("type: {:?}\n", rr.rrtype));
    out.push_str(&format!("class: {:?}\n", rr.class));
    out.push_str(&format!("ttl: {}\n", rr.ttl));
    out.push_str(&format!("{}\n", format_rdata(&rr.rdata)));

    out
}

pub fn format_request(msg: &DnsMessage) -> String {
    let mut out = String::new();

    out.push_str(&";".repeat(60));
    out.push('\n');
    out.push_str(";; REQUEST\n");
    out.push_str(&";".repeat(60));
    out.push('\n');

    out.push_str(&format!(";; id: {}\n", msg.header.id));
    out.push_str(&format!(";; opcode: {}\n", msg.header.opcode));
    out.push_str(&format!(";; recursive: {}\n", msg.header.rd));

    if let Some(q) = msg.questions.first() {
        out.push_str(&format!(";; query: {} ({:?})\n", q.qname, q.qtype));
    }

    out
}

pub fn format_response(msg: &DnsMessage) -> String {
    let mut out = String::new();

    out.push_str(&";".repeat(60));
    out.push('\n');
    out.push_str(";; ANSWER\n");
    out.push_str(&";".repeat(60));
    out.push('\n');

    out.push_str(&format!(";; id: {}\n", msg.header.id));
    out.push_str(&format!(";; opcode: {}\n", msg.header.opcode));
    out.push_str(&format!(";; authoritative: {}\n", msg.header.aa));
    out.push_str(&format!(";; truncated: {}\n", msg.header.tc));
    out.push_str(&format!(";; recursive desired: {}\n", msg.header.rd));
    out.push_str(&format!(";; recursive available: {}\n", msg.header.ra));
    out.push('\n');

    out.push_str(";; ANSWERS\n");
    for rr in &msg.answers {
        out.push_str(&format_resource_record(rr));
    }

    out.push_str(";; AUTHORITIES\n");
    for rr in &msg.authorities {
        out.push_str(&format_resource_record(rr));
    }

    out.push_str(";; ADDITIONALS\n");
    for rr in &msg.additionals {
        out.push_str(&format_resource_record(rr));
    }

    out
}
