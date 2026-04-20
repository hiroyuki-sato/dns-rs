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

#[cfg(test)]
mod tests {
    use super::*;

    use crate::dns::question::Question;
    use crate::dns::resource_record::ResourceRecord;

    #[test]
    fn dns_type_from_u16_known_values() {
        assert_eq!(DnsType::from(1), DnsType::A);
        assert_eq!(DnsType::from(2), DnsType::NS);
        assert_eq!(DnsType::from(5), DnsType::CNAME);
        assert_eq!(DnsType::from(6), DnsType::SOA);
        assert_eq!(DnsType::from(12), DnsType::PTR);
        assert_eq!(DnsType::from(15), DnsType::MX);
        assert_eq!(DnsType::from(16), DnsType::TXT);
        assert_eq!(DnsType::from(28), DnsType::AAAA);
    }

    #[test]
    fn dns_type_from_u16_unknown_value() {
        assert_eq!(DnsType::from(999), DnsType::Unknown(999));
    }

    #[test]
    fn dns_type_into_u16_known_values() {
        assert_eq!(u16::from(DnsType::A), 1);
        assert_eq!(u16::from(DnsType::NS), 2);
        assert_eq!(u16::from(DnsType::CNAME), 5);
        assert_eq!(u16::from(DnsType::SOA), 6);
        assert_eq!(u16::from(DnsType::PTR), 12);
        assert_eq!(u16::from(DnsType::MX), 15);
        assert_eq!(u16::from(DnsType::TXT), 16);
        assert_eq!(u16::from(DnsType::AAAA), 28);
    }

    #[test]
    fn dns_type_into_u16_unknown_value() {
        assert_eq!(u16::from(DnsType::Unknown(999)), 999);
    }

    #[test]
    fn dns_type_roundtrip_known_values() {
        let values = [1u16, 2, 5, 6, 12, 15, 16, 28];

        for value in values {
            let ty = DnsType::from(value);
            assert_eq!(u16::from(ty), value);
        }
    }

    #[test]
    fn dns_type_roundtrip_unknown_value() {
        let value = 65000u16;
        let ty = DnsType::from(value);
        assert_eq!(ty, DnsType::Unknown(value));
        assert_eq!(u16::from(ty), value);
    }

    #[test]
    fn dns_class_from_u16_known_values() {
        assert_eq!(DnsClass::from(1), DnsClass::Internet);
        assert_eq!(DnsClass::from(3), DnsClass::Chaos);
        assert_eq!(DnsClass::from(4), DnsClass::Hesiod);
    }

    #[test]
    fn dns_class_from_u16_unknown_value() {
        assert_eq!(DnsClass::from(999), DnsClass::Unknown(999));
    }

    #[test]
    fn dns_class_into_u16_known_values() {
        assert_eq!(u16::from(DnsClass::Internet), 1);
        assert_eq!(u16::from(DnsClass::Chaos), 3);
        assert_eq!(u16::from(DnsClass::Hesiod), 4);
    }

    #[test]
    fn dns_class_into_u16_unknown_value() {
        assert_eq!(u16::from(DnsClass::Unknown(999)), 999);
    }

    #[test]
    fn dns_class_roundtrip_known_values() {
        let values = [1u16, 3, 4];

        for value in values {
            let class = DnsClass::from(value);
            assert_eq!(u16::from(class), value);
        }
    }

    #[test]
    fn dns_class_roundtrip_unknown_value() {
        let value = 65000u16;
        let class = DnsClass::from(value);
        assert_eq!(class, DnsClass::Unknown(value));
        assert_eq!(u16::from(class), value);
    }

    #[test]
    fn question_can_be_constructed() {
        let question = Question {
            qname: "example.com".to_string(),
            qtype: DnsType::A,
            qclass: DnsClass::Internet,
        };

        assert_eq!(question.qname, "example.com");
        assert_eq!(question.qtype, DnsType::A);
        assert_eq!(question.qclass, DnsClass::Internet);
    }

    #[test]
    fn resource_record_with_a_rdata_can_be_constructed() {
        let rr = ResourceRecord {
            name: "example.com".to_string(),
            rrtype: DnsType::A,
            class: DnsClass::Internet,
            ttl: 300,
            rdata: RData::A([93, 184, 216, 34]),
        };

        assert_eq!(rr.name, "example.com");
        assert_eq!(rr.rrtype, DnsType::A);
        assert_eq!(rr.class, DnsClass::Internet);
        assert_eq!(rr.ttl, 300);
        assert_eq!(rr.rdata, RData::A([93, 184, 216, 34]));
    }

    #[test]
    fn resource_record_with_complex_rdata_can_be_constructed() {
        let rr = ResourceRecord {
            name: "example.com".to_string(),
            rrtype: DnsType::MX,
            class: DnsClass::Internet,
            ttl: 600,
            rdata: RData::MX {
                preference: 10,
                exchange: "mail.example.com".to_string(),
            },
        };

        assert_eq!(rr.rrtype, DnsType::MX);
        assert_eq!(
            rr.rdata,
            RData::MX {
                preference: 10,
                exchange: "mail.example.com".to_string(),
            }
        );
    }

    #[test]
    fn rdata_unknown_preserves_bytes() {
        let data = vec![0xde, 0xad, 0xbe, 0xef];
        let rdata = RData::Unknown(data.clone());

        assert_eq!(rdata, RData::Unknown(data));
    }
}
