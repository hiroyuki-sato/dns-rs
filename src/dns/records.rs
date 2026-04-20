// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1

// The header contains the following fields:
//                                 1  1  1  1  1  1
//   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                      ID                       |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    QDCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    ANCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    NSCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    ARCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

#[derive(Debug, PartialEq, Eq)]
pub struct Header {
    pub id: u16,
    pub qr: bool,
    pub opcode: u8,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub z: u8,
    pub rcode: u8,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

#[derive(Debug, PartialEq, Eq)]

pub struct Question {
    pub qname: DomainName,
    pub qtype: DnsType,
    pub qclass: DnsClass,
}

pub type DomainName = String;
pub type Text = Vec<Vec<u8>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    A([u8; 4]),
    AAAA([u8; 16]),
    CNAME(DomainName),
    NS(DomainName),
    PTR(DomainName),
    MX {
        preference: u16,
        exchange: DomainName,
    },
    SOA {
        mname: DomainName,
        rname: DomainName,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    TXT(Text),
    Unknown(Vec<u8>),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DnsType {
    A,     // 1
    NS,    // 2
    CNAME, // 5
    SOA,   // 6
    PTR,   // 12
    MX,    // 15
    TXT,   // 16
    AAAA,  // 28
    Unknown(u16),
}

impl From<u16> for DnsType {
    fn from(n: u16) -> Self {
        match n {
            1 => DnsType::A,
            2 => DnsType::NS,
            5 => DnsType::CNAME,
            6 => DnsType::SOA,
            12 => DnsType::PTR,
            15 => DnsType::MX,
            16 => DnsType::TXT,
            28 => DnsType::AAAA,
            _ => DnsType::Unknown(n),
        }
    }
}

impl From<DnsType> for u16 {
    fn from(t: DnsType) -> u16 {
        match t {
            DnsType::A => 1,
            DnsType::NS => 2,
            DnsType::CNAME => 5,
            DnsType::SOA => 6,
            DnsType::PTR => 12,
            DnsType::MX => 15,
            DnsType::TXT => 16,
            DnsType::AAAA => 28,
            DnsType::Unknown(n) => n,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRecord {
    pub name: DomainName,
    pub rrtype: DnsType,
    pub class: DnsClass,
    pub ttl: u32,
    pub rdata: RData,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DnsClass {
    Internet, // IN = 1
    Chaos,    // CH = 3
    Hesiod,   // HS = 4
    Unknown(u16),
}

impl From<u16> for DnsClass {
    fn from(n: u16) -> Self {
        match n {
            1 => DnsClass::Internet,
            3 => DnsClass::Chaos,
            4 => DnsClass::Hesiod,
            _ => DnsClass::Unknown(n),
        }
    }
}

impl From<DnsClass> for u16 {
    fn from(c: DnsClass) -> u16 {
        match c {
            DnsClass::Internet => 1,
            DnsClass::Chaos => 3,
            DnsClass::Hesiod => 4,
            DnsClass::Unknown(n) => n,
        }
    }
}
