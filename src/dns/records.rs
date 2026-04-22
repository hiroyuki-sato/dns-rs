pub type DomainName = String;
pub type Text = Vec<Vec<u8>>;

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

impl core::fmt::Display for DnsClass {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DnsClass::Internet => write!(f, "IN"),
            DnsClass::Chaos => write!(f, "CH"),
            DnsClass::Hesiod => write!(f, "HS"),
            DnsClass::Unknown(n) => write!(f, "Unknown({})", n),
        }
    }
}
