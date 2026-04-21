use crate::dns::error::DnsError;
use crate::dns::name::{decode_name, encode_name_uncompressed};
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
    pub fn encode(&self, writer: &mut wire::Writer) -> Result<(), DnsError> {
        let enc_name = encode_name_uncompressed(&self.name)?;
        writer.write_slice(&enc_name);
        writer.write_u16_be(self.rrtype.into());
        writer.write_u16_be(self.class.into());
        writer.write_u32_be(self.ttl);

        // Encode RDATA into a temporary buffer first.
        //
        // RDLENGTH (the length of RDATA) must be written before the actual RDATA,
        // but its value is only known after encoding the RDATA itself.
        // Therefore, we encode RDATA into a temporary writer to measure its size,
        // then write the length followed by the encoded bytes to the main writer.
        let mut rdata_writer = wire::Writer::new();
        self.rdata.encode(&mut rdata_writer)?;
        let rdata = rdata_writer.into_inner();
        writer.write_u16_be(rdata.len() as u16);
        writer.write_slice(&rdata);
        Ok(())
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

    // ------------------------------------------------------------
    // Resource record encoder tests
    // Everything below this line tests encoding behavior.
    // ------------------------------------------------------------

    #[test]
    fn encode_resource_record_writes_a_record() {
        let rr = ResourceRecord {
            name: "example.com".to_string(),
            rrtype: DnsType::A,
            class: DnsClass::Internet,
            ttl: 300,
            rdata: RData::A([93, 184, 216, 34]),
        };

        let mut writer = wire::Writer::new();
        rr.encode(&mut writer).unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&qname_bytes("example.com"));
        push_u16_be(&mut expected, 1); // TYPE A
        push_u16_be(&mut expected, 1); // CLASS IN
        push_u32_be(&mut expected, 300);
        push_u16_be(&mut expected, 4); // RDLENGTH
        expected.extend_from_slice(&[93, 184, 216, 34]);

        assert_eq!(writer.into_inner(), expected);
    }

    #[test]
    fn encode_resource_record_writes_aaaa_record() {
        let rr = ResourceRecord {
            name: "example.com".to_string(),
            rrtype: DnsType::AAAA,
            class: DnsClass::Internet,
            ttl: 300,
            rdata: RData::AAAA([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        };

        let mut writer = wire::Writer::new();
        rr.encode(&mut writer).unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&qname_bytes("example.com"));
        push_u16_be(&mut expected, 28); // TYPE AAAA
        push_u16_be(&mut expected, 1); // CLASS IN
        push_u32_be(&mut expected, 300);
        push_u16_be(&mut expected, 16); // RDLENGTH
        expected.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

        assert_eq!(writer.into_inner(), expected);
    }

    #[test]
    fn encode_resource_record_writes_cname_record() {
        let rr = ResourceRecord {
            name: "www.example.com".to_string(),
            rrtype: DnsType::CNAME,
            class: DnsClass::Internet,
            ttl: 60,
            rdata: RData::CNAME("example.com".to_string()),
        };

        let mut writer = wire::Writer::new();
        rr.encode(&mut writer).unwrap();

        let rdata = qname_bytes("example.com");

        let mut expected = Vec::new();
        expected.extend_from_slice(&qname_bytes("www.example.com"));
        push_u16_be(&mut expected, 5); // TYPE CNAME
        push_u16_be(&mut expected, 1); // CLASS IN
        push_u32_be(&mut expected, 60);
        push_u16_be(&mut expected, rdata.len() as u16);
        expected.extend_from_slice(&rdata);

        assert_eq!(writer.into_inner(), expected);
    }

    #[test]
    fn encode_resource_record_writes_ns_record() {
        let rr = ResourceRecord {
            name: "example.com".to_string(),
            rrtype: DnsType::NS,
            class: DnsClass::Internet,
            ttl: 3600,
            rdata: RData::NS("ns1.example.com".to_string()),
        };

        let mut writer = wire::Writer::new();
        rr.encode(&mut writer).unwrap();

        let rdata = qname_bytes("ns1.example.com");

        let mut expected = Vec::new();
        expected.extend_from_slice(&qname_bytes("example.com"));
        push_u16_be(&mut expected, 2); // TYPE NS
        push_u16_be(&mut expected, 1); // CLASS IN
        push_u32_be(&mut expected, 3600);
        push_u16_be(&mut expected, rdata.len() as u16);
        expected.extend_from_slice(&rdata);

        assert_eq!(writer.into_inner(), expected);
    }

    #[test]
    fn encode_resource_record_writes_ptr_record() {
        let rr = ResourceRecord {
            name: "4.3.2.1.in-addr.arpa".to_string(),
            rrtype: DnsType::PTR,
            class: DnsClass::Internet,
            ttl: 120,
            rdata: RData::PTR("host.example.com".to_string()),
        };

        let mut writer = wire::Writer::new();
        rr.encode(&mut writer).unwrap();

        let rdata = qname_bytes("host.example.com");

        let mut expected = Vec::new();
        expected.extend_from_slice(&qname_bytes("4.3.2.1.in-addr.arpa"));
        push_u16_be(&mut expected, 12); // TYPE PTR
        push_u16_be(&mut expected, 1); // CLASS IN
        push_u32_be(&mut expected, 120);
        push_u16_be(&mut expected, rdata.len() as u16);
        expected.extend_from_slice(&rdata);

        assert_eq!(writer.into_inner(), expected);
    }

    #[test]
    fn encode_resource_record_writes_mx_record() {
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

        let mut writer = wire::Writer::new();
        rr.encode(&mut writer).unwrap();

        let mut rdata = Vec::new();
        push_u16_be(&mut rdata, 10);
        rdata.extend_from_slice(&qname_bytes("mail.example.com"));

        let mut expected = Vec::new();
        expected.extend_from_slice(&qname_bytes("example.com"));
        push_u16_be(&mut expected, 15); // TYPE MX
        push_u16_be(&mut expected, 1); // CLASS IN
        push_u32_be(&mut expected, 600);
        push_u16_be(&mut expected, rdata.len() as u16);
        expected.extend_from_slice(&rdata);

        assert_eq!(writer.into_inner(), expected);
    }

    #[test]
    fn encode_resource_record_writes_soa_record() {
        let rr = ResourceRecord {
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
        };

        let mut writer = wire::Writer::new();
        rr.encode(&mut writer).unwrap();

        let mut rdata = Vec::new();
        rdata.extend_from_slice(&qname_bytes("ns1.example.com"));
        rdata.extend_from_slice(&qname_bytes("hostmaster.example.com"));
        push_u32_be(&mut rdata, 20240101);
        push_u32_be(&mut rdata, 7200);
        push_u32_be(&mut rdata, 3600);
        push_u32_be(&mut rdata, 1209600);
        push_u32_be(&mut rdata, 3600);

        let mut expected = Vec::new();
        expected.extend_from_slice(&qname_bytes("example.com"));
        push_u16_be(&mut expected, 6); // TYPE SOA
        push_u16_be(&mut expected, 1); // CLASS IN
        push_u32_be(&mut expected, 3600);
        push_u16_be(&mut expected, rdata.len() as u16);
        expected.extend_from_slice(&rdata);

        assert_eq!(writer.into_inner(), expected);
    }

    #[test]
    fn encode_resource_record_writes_txt_record() {
        let rr = ResourceRecord {
            name: "example.com".to_string(),
            rrtype: DnsType::TXT,
            class: DnsClass::Internet,
            ttl: 300,
            rdata: RData::TXT(vec![b"hello".to_vec(), b"world".to_vec()]),
        };

        let mut writer = wire::Writer::new();
        rr.encode(&mut writer).unwrap();

        let txt_data = vec![
            5, b'h', b'e', b'l', b'l', b'o', 5, b'w', b'o', b'r', b'l', b'd',
        ];

        let mut expected = Vec::new();
        expected.extend_from_slice(&qname_bytes("example.com"));
        push_u16_be(&mut expected, 16); // TYPE TXT
        push_u16_be(&mut expected, 1); // CLASS IN
        push_u32_be(&mut expected, 300);
        push_u16_be(&mut expected, txt_data.len() as u16);
        expected.extend_from_slice(&txt_data);

        assert_eq!(writer.into_inner(), expected);
    }

    #[test]
    fn encode_resource_record_writes_unknown_record() {
        let rr = ResourceRecord {
            name: "example.com".to_string(),
            rrtype: DnsType::Unknown(65000),
            class: DnsClass::Internet,
            ttl: 300,
            rdata: RData::Unknown(vec![0xde, 0xad, 0xbe, 0xef]),
        };

        let mut writer = wire::Writer::new();
        rr.encode(&mut writer).unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&qname_bytes("example.com"));
        push_u16_be(&mut expected, 65000);
        push_u16_be(&mut expected, 1);
        push_u32_be(&mut expected, 300);
        push_u16_be(&mut expected, 4);
        expected.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);

        assert_eq!(writer.into_inner(), expected);
    }

    #[test]
    fn encode_resource_record_rejects_invalid_name() {
        let rr = ResourceRecord {
            name: format!("{}.com", "a".repeat(64)),
            rrtype: DnsType::A,
            class: DnsClass::Internet,
            ttl: 300,
            rdata: RData::A([93, 184, 216, 34]),
        };

        let mut writer = wire::Writer::new();
        let err = rr.encode(&mut writer).unwrap_err();

        assert_eq!(err, DnsError::LabelTooLong);
    }

    #[test]
    fn encode_resource_record_rejects_invalid_rdata() {
        let rr = ResourceRecord {
            name: "example.com".to_string(),
            rrtype: DnsType::TXT,
            class: DnsClass::Internet,
            ttl: 300,
            rdata: RData::TXT(vec![vec![b'a'; 256]]),
        };

        let mut writer = wire::Writer::new();
        let err = rr.encode(&mut writer).unwrap_err();

        assert_eq!(
            err,
            DnsError::InvalidRdataLength {
                expected: 255,
                actual: 256,
            }
        );
    }

    #[test]
    fn encode_then_decode_resource_record_roundtrip_a() {
        let original = ResourceRecord {
            name: "example.com".to_string(),
            rrtype: DnsType::A,
            class: DnsClass::Internet,
            ttl: 300,
            rdata: RData::A([93, 184, 216, 34]),
        };

        let mut writer = wire::Writer::new();
        original.encode(&mut writer).unwrap();
        let encoded = writer.into_inner();

        let mut reader = wire::Reader::new(&encoded);
        let decoded = ResourceRecord::decode(&mut reader).unwrap();

        assert_eq!(decoded, original);
    }

    #[test]
    fn encode_then_decode_resource_record_roundtrip_mx() {
        let original = ResourceRecord {
            name: "example.com".to_string(),
            rrtype: DnsType::MX,
            class: DnsClass::Internet,
            ttl: 600,
            rdata: RData::MX {
                preference: 10,
                exchange: "mail.example.com".to_string(),
            },
        };

        let mut writer = wire::Writer::new();
        original.encode(&mut writer).unwrap();
        let encoded = writer.into_inner();

        let mut reader = wire::Reader::new(&encoded);
        let decoded = ResourceRecord::decode(&mut reader).unwrap();

        assert_eq!(decoded, original);
    }

    #[test]
    fn encode_then_decode_resource_record_roundtrip_txt() {
        let original = ResourceRecord {
            name: "example.com".to_string(),
            rrtype: DnsType::TXT,
            class: DnsClass::Internet,
            ttl: 300,
            rdata: RData::TXT(vec![b"hello".to_vec(), b"world".to_vec()]),
        };

        let mut writer = wire::Writer::new();
        original.encode(&mut writer).unwrap();
        let encoded = writer.into_inner();

        let mut reader = wire::Reader::new(&encoded);
        let decoded = ResourceRecord::decode(&mut reader).unwrap();

        assert_eq!(decoded, original);
    }

    // ------------------------------------------------------------
    // End of encoder tests
    // ------------------------------------------------------------
}
