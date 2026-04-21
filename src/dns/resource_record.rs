use crate::dns::error::DnsError;
use crate::dns::name::decode_name;
use crate::dns::records::{DnsClass, DnsType, DomainName, RData};
use crate::wire;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRecord {
    pub name: DomainName,
    pub rrtype: DnsType,
    pub class: DnsClass,
    pub ttl: u32,
    pub rdata: RData,
}

impl ResourceRecord {
    pub fn decode(reader: &mut wire::Reader<'_>) -> Result<Self, DnsError> {
        let name = decode_name(reader)?;
        let rrtype = DnsType::from(reader.read_u16_be()?);
        let class = DnsClass::from(reader.read_u16_be()?);
        let ttl = reader.read_u32_be()?;
        let rdlength = reader.read_u16_be()? as usize;
        let rdata = RData::decode(reader, rrtype, rdlength)?;

        Ok(Self {
            name,
            rrtype,
            class,
            ttl,
            rdata,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // ------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------

    fn qname_bytes(name: &str) -> Vec<u8> {
        let mut out = Vec::new();

        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }

        out.push(0);
        out
    }

    fn push_u16_be(buf: &mut Vec<u8>, value: u16) {
        buf.extend_from_slice(&value.to_be_bytes());
    }

    fn push_u32_be(buf: &mut Vec<u8>, value: u32) {
        buf.extend_from_slice(&value.to_be_bytes());
    }

    // ------------------------------------------------------------
    // Resource record decoder tests
    // ------------------------------------------------------------

    #[test]
    fn decode_resource_record_reads_a_record() {
        let mut buf = Vec::new();

        buf.extend_from_slice(&qname_bytes("example.com"));
        push_u16_be(&mut buf, 1); // TYPE A
        push_u16_be(&mut buf, 1); // CLASS IN
        push_u32_be(&mut buf, 300);
        push_u16_be(&mut buf, 4); // RDLENGTH
        buf.extend_from_slice(&[93, 184, 216, 34]);

        let mut reader = wire::Reader::new(&buf);

        let rr = ResourceRecord::decode(&mut reader).unwrap();

        assert_eq!(
            rr,
            ResourceRecord {
                name: "example.com".to_string(),
                rrtype: DnsType::A,
                class: DnsClass::Internet,
                ttl: 300,
                rdata: RData::A([93, 184, 216, 34]),
            }
        );
    }

    #[test]
    fn decode_resource_record_reads_aaaa_record() {
        let mut buf = Vec::new();

        buf.extend_from_slice(&qname_bytes("example.com"));
        push_u16_be(&mut buf, 28); // TYPE AAAA
        push_u16_be(&mut buf, 1); // CLASS IN
        push_u32_be(&mut buf, 300);
        push_u16_be(&mut buf, 16); // RDLENGTH
        buf.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

        let mut reader = wire::Reader::new(&buf);

        let rr = ResourceRecord::decode(&mut reader).unwrap();

        assert_eq!(
            rr,
            ResourceRecord {
                name: "example.com".to_string(),
                rrtype: DnsType::AAAA,
                class: DnsClass::Internet,
                ttl: 300,
                rdata: RData::AAAA([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,]),
            }
        );
    }

    #[test]
    fn decode_resource_record_reads_cname_record() {
        let mut buf = Vec::new();

        buf.extend_from_slice(&qname_bytes("www.example.com"));
        push_u16_be(&mut buf, 5); // TYPE CNAME
        push_u16_be(&mut buf, 1); // CLASS IN
        push_u32_be(&mut buf, 60);

        let rdata = qname_bytes("example.com");
        push_u16_be(&mut buf, rdata.len() as u16);
        buf.extend_from_slice(&rdata);

        let mut reader = wire::Reader::new(&buf);

        let rr = ResourceRecord::decode(&mut reader).unwrap();

        assert_eq!(
            rr,
            ResourceRecord {
                name: "www.example.com".to_string(),
                rrtype: DnsType::CNAME,
                class: DnsClass::Internet,
                ttl: 60,
                rdata: RData::CNAME("example.com".to_string()),
            }
        );
    }

    #[test]
    fn decode_resource_record_reads_ns_record() {
        let mut buf = Vec::new();

        buf.extend_from_slice(&qname_bytes("example.com"));
        push_u16_be(&mut buf, 2); // TYPE NS
        push_u16_be(&mut buf, 1); // CLASS IN
        push_u32_be(&mut buf, 3600);

        let rdata = qname_bytes("ns1.example.com");
        push_u16_be(&mut buf, rdata.len() as u16);
        buf.extend_from_slice(&rdata);

        let mut reader = wire::Reader::new(&buf);

        let rr = ResourceRecord::decode(&mut reader).unwrap();

        assert_eq!(
            rr,
            ResourceRecord {
                name: "example.com".to_string(),
                rrtype: DnsType::NS,
                class: DnsClass::Internet,
                ttl: 3600,
                rdata: RData::NS("ns1.example.com".to_string()),
            }
        );
    }

    #[test]
    fn decode_resource_record_reads_ptr_record() {
        let mut buf = Vec::new();

        buf.extend_from_slice(&qname_bytes("4.3.2.1.in-addr.arpa"));
        push_u16_be(&mut buf, 12); // TYPE PTR
        push_u16_be(&mut buf, 1); // CLASS IN
        push_u32_be(&mut buf, 120);

        let rdata = qname_bytes("host.example.com");
        push_u16_be(&mut buf, rdata.len() as u16);
        buf.extend_from_slice(&rdata);

        let mut reader = wire::Reader::new(&buf);

        let rr = ResourceRecord::decode(&mut reader).unwrap();

        assert_eq!(
            rr,
            ResourceRecord {
                name: "4.3.2.1.in-addr.arpa".to_string(),
                rrtype: DnsType::PTR,
                class: DnsClass::Internet,
                ttl: 120,
                rdata: RData::PTR("host.example.com".to_string()),
            }
        );
    }

    #[test]
    fn decode_resource_record_reads_mx_record() {
        let mut buf = Vec::new();

        buf.extend_from_slice(&qname_bytes("example.com"));
        push_u16_be(&mut buf, 15); // TYPE MX
        push_u16_be(&mut buf, 1); // CLASS IN
        push_u32_be(&mut buf, 600);

        let exchange = qname_bytes("mail.example.com");
        let rdlength = 2 + exchange.len();
        push_u16_be(&mut buf, rdlength as u16);
        push_u16_be(&mut buf, 10); // preference
        buf.extend_from_slice(&exchange);

        let mut reader = wire::Reader::new(&buf);

        let rr = ResourceRecord::decode(&mut reader).unwrap();

        assert_eq!(
            rr,
            ResourceRecord {
                name: "example.com".to_string(),
                rrtype: DnsType::MX,
                class: DnsClass::Internet,
                ttl: 600,
                rdata: RData::MX {
                    preference: 10,
                    exchange: "mail.example.com".to_string(),
                },
            }
        );
    }

    #[test]
    fn decode_resource_record_reads_soa_record() {
        let mut buf = Vec::new();

        buf.extend_from_slice(&qname_bytes("example.com"));
        push_u16_be(&mut buf, 6); // TYPE SOA
        push_u16_be(&mut buf, 1); // CLASS IN
        push_u32_be(&mut buf, 3600);

        let mut rdata = Vec::new();
        rdata.extend_from_slice(&qname_bytes("ns1.example.com"));
        rdata.extend_from_slice(&qname_bytes("hostmaster.example.com"));
        push_u32_be(&mut rdata, 20240101);
        push_u32_be(&mut rdata, 7200);
        push_u32_be(&mut rdata, 3600);
        push_u32_be(&mut rdata, 1209600);
        push_u32_be(&mut rdata, 3600);

        push_u16_be(&mut buf, rdata.len() as u16);
        buf.extend_from_slice(&rdata);

        let mut reader = wire::Reader::new(&buf);

        let rr = ResourceRecord::decode(&mut reader).unwrap();

        assert_eq!(
            rr,
            ResourceRecord {
                name: "example.com".to_string(),
                rrtype: DnsType::SOA,
                class: DnsClass::Internet,
                ttl: 3600,
                rdata: RData::SOA {
                    mname: "ns1.example.com".to_string(),
                    rname: "hostmaster.example.com".to_string(),
                    serial: 20240101,
                    refresh: 7200,
                    retry: 3600,
                    expire: 1209600,
                    minimum: 3600,
                },
            }
        );
    }

    #[test]
    fn decode_resource_record_reads_txt_record() {
        let mut buf = Vec::new();

        buf.extend_from_slice(&qname_bytes("example.com"));
        push_u16_be(&mut buf, 16); // TYPE TXT
        push_u16_be(&mut buf, 1); // CLASS IN
        push_u32_be(&mut buf, 300);

        let txt_data = vec![
            5, b'h', b'e', b'l', b'l', b'o', 5, b'w', b'o', b'r', b'l', b'd',
        ];
        push_u16_be(&mut buf, txt_data.len() as u16);
        buf.extend_from_slice(&txt_data);

        let mut reader = wire::Reader::new(&buf);

        let rr = ResourceRecord::decode(&mut reader).unwrap();

        assert_eq!(
            rr,
            ResourceRecord {
                name: "example.com".to_string(),
                rrtype: DnsType::TXT,
                class: DnsClass::Internet,
                ttl: 300,
                rdata: RData::TXT(vec![b"hello".to_vec(), b"world".to_vec()]),
            }
        );
    }

    #[test]
    fn decode_resource_record_preserves_unknown_record_data() {
        let mut buf = Vec::new();

        buf.extend_from_slice(&qname_bytes("example.com"));
        push_u16_be(&mut buf, 65000); // TYPE unknown
        push_u16_be(&mut buf, 1); // CLASS IN
        push_u32_be(&mut buf, 300);

        let raw = vec![0xde, 0xad, 0xbe, 0xef];
        push_u16_be(&mut buf, raw.len() as u16);
        buf.extend_from_slice(&raw);

        let mut reader = wire::Reader::new(&buf);

        let rr = ResourceRecord::decode(&mut reader).unwrap();

        assert_eq!(
            rr,
            ResourceRecord {
                name: "example.com".to_string(),
                rrtype: DnsType::Unknown(65000),
                class: DnsClass::Internet,
                ttl: 300,
                rdata: RData::Unknown(vec![0xde, 0xad, 0xbe, 0xef]),
            }
        );
    }

    #[test]
    fn decode_resource_record_rejects_invalid_a_rdata_length() {
        let mut buf = Vec::new();

        buf.extend_from_slice(&qname_bytes("example.com"));
        push_u16_be(&mut buf, 1); // TYPE A
        push_u16_be(&mut buf, 1); // CLASS IN
        push_u32_be(&mut buf, 300);
        push_u16_be(&mut buf, 3); // invalid RDLENGTH for A
        buf.extend_from_slice(&[1, 2, 3]);

        let mut reader = wire::Reader::new(&buf);

        let err = ResourceRecord::decode(&mut reader).unwrap_err();

        assert_eq!(
            err,
            DnsError::InvalidRdataLength {
                expected: 4,
                actual: 3,
            }
        );
    }
}
