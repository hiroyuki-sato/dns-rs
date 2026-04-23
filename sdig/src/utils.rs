use std::net::{Ipv4Addr, Ipv6Addr};

use is_terminal::IsTerminal;
use owo_colors::OwoColorize;

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
    format!(
        "{}\t{}\t{}\t{:?}\t{}\n",
        rr.name,
        rr.ttl,
        rr.class,
        rr.rrtype,
        format_rdata(&rr.rdata),
    )
}

pub fn format_request(msg: &DnsMessage) -> String {
    let mut out = String::new();

    let text_color: Color = if std::io::stdout().is_terminal() {
        Color::Blue
    } else {
        Color::None
    };

    out.push_str(&colorize(&";".repeat(60), &text_color));
    out.push('\n');
    out.push_str(&colorize(";; REQUEST\n", &text_color));
    out.push_str(&colorize(&";".repeat(60), &text_color));
    out.push('\n');

    out.push_str(&format!(
        "{}: {}\n",
        colorize(";; id             ", &text_color),
        msg.header.id
    ));

    out.push_str(&format!(
        "{}: {}\n",
        colorize(";; recursive req  ", &text_color),
        msg.header.rd
    ));

    if let Some(q) = msg.questions.first() {
        out.push_str(&format!(
            "{}: {} ({:?})\n",
            colorize(";; query          ", &text_color),
            q.qname,
            q.qtype
        ));
    }
    out.push('\n');

    out
}
pub fn format_response(msg: &DnsMessage) -> String {
    let mut out = String::new();

    let text_color: Color = if std::io::stdout().is_terminal() {
        Color::Magenta
    } else {
        Color::None
    };

    out.push_str(&colorize(&";".repeat(60), &text_color));
    out.push('\n');
    out.push_str(&colorize(";; ANSWER\n", &text_color));
    out.push_str(&colorize(&";".repeat(60), &text_color));
    out.push('\n');

    out.push_str(&format!(
        "{}: {}\n",
        colorize(";; id             ", &text_color),
        msg.header.id
    ));
    out.push_str(&format!(
        "{}: {}\n",
        colorize(";; opcode         ", &text_color),
        msg.header.opcode
    ));
    out.push_str(&format!(
        "{}: {}\n",
        colorize(";; authoritative  ", &text_color),
        msg.header.aa
    ));
    out.push_str(&format!(
        "{}: {}\n",
        colorize(";; truncated      ", &text_color),
        msg.header.tc
    ));
    out.push_str(&format!(
        "{}: {}\n",
        colorize(";; recursive req  ", &text_color),
        msg.header.rd
    ));
    out.push_str(&format!(
        "{}: {}\n",
        colorize(";; recursive avail", &text_color),
        msg.header.ra
    ));
    out.push_str(&format!(
        "{}: {:?}\n",
        colorize(";; status         ", &text_color),
        msg.header.rcode
    ));

    out.push('\n');

    out.push_str(&colorize(";; ANSWERS\n", &text_color));
    for rr in &msg.answers {
        out.push_str(&format_resource_record(rr));
    }

    out.push_str(&colorize(";; AUTHORITIES\n", &text_color));
    for rr in &msg.authorities {
        out.push_str(&format_resource_record(rr));
    }

    out.push_str(&colorize(";; ADDITIONALS\n", &text_color));
    for rr in &msg.additionals {
        out.push_str(&format_resource_record(rr));
    }

    out
}

#[allow(dead_code)] // reserved for future color usage
enum Color {
    Black,
    Blue,
    Cyan,
    Green,
    Magenta,
    Red,
    Yellow,
    White,
    None,
}

fn colorize(s: &str, c: &Color) -> String {
    match c {
        Color::Black => format!("{}", s.black()),
        Color::Blue => format!("{}", s.blue()),
        Color::Cyan => format!("{}", s.cyan()),
        Color::Green => format!("{}", s.green()),
        Color::Magenta => format!("{}", s.magenta()),
        Color::Red => format!("{}", s.red()),
        Color::Yellow => format!("{}", s.yellow()),
        Color::White => format!("{}", s.white()),
        Color::None => s.to_string(),
    }
}
