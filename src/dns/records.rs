use crate::dns::error::DnsError;
use crate::dns::name::{decode_name, encode_name_uncompressed};
use crate::wire;

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

impl RData {
    pub fn decode(
        reader: &mut wire::Reader<'_>,
        rrtype: DnsType,
        rdlength: usize, // Decode RDATA based on TYPE.
    ) -> Result<Self, DnsError> {
        let rdata = match rrtype {
            DnsType::A => {
                if rdlength != 4 {
                    return Err(DnsError::InvalidRdataLength {
                        expected: 4,
                        actual: rdlength,
                    });
                }

                RData::A(reader.read_array::<4>()?)
            }

            DnsType::AAAA => {
                if rdlength != 16 {
                    return Err(DnsError::InvalidRdataLength {
                        expected: 16,
                        actual: rdlength,
                    });
                }

                RData::AAAA(reader.read_array::<16>()?)
            }

            DnsType::CNAME => {
                let cname = Self::decode_name_rdata(reader, rdlength)?;
                RData::CNAME(cname)
            }

            DnsType::NS => {
                let ns = Self::decode_name_rdata(reader, rdlength)?;
                RData::NS(ns)
            }

            DnsType::PTR => {
                let ptr = Self::decode_name_rdata(reader, rdlength)?;
                RData::PTR(ptr)
            }

            DnsType::MX => {
                let start = reader.position();

                let preference = reader.read_u16_be()?;
                let exchange = decode_name(reader)?;

                let consumed = reader.position() - start;
                if consumed != rdlength {
                    return Err(DnsError::InvalidRdataLength {
                        expected: rdlength,
                        actual: consumed,
                    });
                }

                RData::MX {
                    preference,
                    exchange,
                }
            }

            DnsType::SOA => {
                let start = reader.position();

                let mname = decode_name(reader)?;
                let rname = decode_name(reader)?;
                let serial = reader.read_u32_be()?;
                let refresh = reader.read_u32_be()?;
                let retry = reader.read_u32_be()?;
                let expire = reader.read_u32_be()?;
                let minimum = reader.read_u32_be()?;

                let consumed = reader.position() - start;
                if consumed != rdlength {
                    return Err(DnsError::InvalidRdataLength {
                        expected: rdlength,
                        actual: consumed,
                    });
                }

                RData::SOA {
                    mname,
                    rname,
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
                }
            }

            DnsType::TXT => {
                let txt_bytes = reader.read_slice(rdlength)?;
                let txt = Self::decode_txt_rdata(txt_bytes)?;
                RData::TXT(txt)
            }

            DnsType::Unknown(_) => {
                let raw = reader.read_slice(rdlength)?.to_vec();
                RData::Unknown(raw)
            }
        };

        Ok(rdata)
    }

    fn decode_name_rdata(
        reader: &mut wire::Reader<'_>,
        rdlength: usize,
    ) -> Result<DomainName, DnsError> {
        let start = reader.position();

        let name = decode_name(reader)?;

        let consumed = reader.position() - start;
        if consumed != rdlength {
            return Err(DnsError::InvalidRdataLength {
                expected: rdlength,
                actual: consumed,
            });
        }

        Ok(name)
    }

    fn decode_txt_rdata(mut buf: &[u8]) -> Result<Text, DnsError> {
        let mut out = Vec::new();

        // TXT RDATA is one or more length-prefixed character strings.
        while !buf.is_empty() {
            let len = buf[0] as usize;
            buf = &buf[1..];

            if buf.len() < len {
                return Err(DnsError::InvalidRdataLength {
                    expected: len,
                    actual: buf.len(),
                });
            }

            out.push(buf[..len].to_vec());
            buf = &buf[len..];
        }

        Ok(out)
    }

    // --------------------------------------
    // encode
    // --------------------------------------
    pub fn encode(&self, writer: &mut wire::Writer) -> Result<(), DnsError> {
        match self {
            RData::A(addr) => writer.write_array(addr),
            RData::AAAA(addr) => writer.write_array(addr),
            RData::CNAME(name) => {
                let encoded = encode_name_uncompressed(name)?;
                writer.write_slice(&encoded);
            }
            RData::NS(name) => {
                let encoded = encode_name_uncompressed(name)?;
                writer.write_slice(&encoded);
            }
            RData::PTR(name) => {
                let encoded = encode_name_uncompressed(name)?;
                writer.write_slice(&encoded);
            }
            RData::MX {
                preference,
                exchange,
            } => {
                writer.write_u16_be(*preference);
                let encoded = encode_name_uncompressed(exchange)?;
                writer.write_slice(&encoded);
            }
            RData::SOA {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                let mname = encode_name_uncompressed(mname)?;
                writer.write_slice(&mname);
                let rname = encode_name_uncompressed(rname)?;
                writer.write_slice(&rname);
                writer.write_u32_be(*serial);
                writer.write_u32_be(*refresh);
                writer.write_u32_be(*retry);
                writer.write_u32_be(*expire);
                writer.write_u32_be(*minimum);
            }
            RData::TXT(texts) => {
                for txt in texts {
                    if txt.len() > 255 {
                        return Err(DnsError::InvalidRdataLength {
                            expected: 255,
                            actual: txt.len(),
                        });
                    }
                    writer.write_u8(txt.len() as u8);
                    writer.write_slice(txt);
                }
            }
            RData::Unknown(data) => writer.write_slice(data),
        }
        Ok(())
    }
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

    // ------------------------------------------------------------
    // RData decoder tests
    // ------------------------------------------------------------

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

    // ------------------------------------------------------------
    // encode test helpers
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
    // RData encoder tests
    // ------------------------------------------------------------

    #[test]
    fn rdata_a_can_be_encoded() {
        let rdata = RData::A([93, 184, 216, 34]);
        let mut writer = wire::Writer::new();

        rdata.encode(&mut writer).unwrap();

        assert_eq!(writer.into_inner(), vec![93, 184, 216, 34]);
    }

    #[test]
    fn rdata_aaaa_can_be_encoded() {
        let rdata = RData::AAAA([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let mut writer = wire::Writer::new();

        rdata.encode(&mut writer).unwrap();

        assert_eq!(
            writer.into_inner(),
            vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,]
        );
    }

    #[test]
    fn rdata_cname_can_be_encoded() {
        let rdata = RData::CNAME("example.com".to_string());
        let mut writer = wire::Writer::new();

        rdata.encode(&mut writer).unwrap();

        assert_eq!(writer.into_inner(), qname_bytes("example.com"));
    }

    #[test]
    fn rdata_ns_can_be_encoded() {
        let rdata = RData::NS("ns1.example.com".to_string());
        let mut writer = wire::Writer::new();

        rdata.encode(&mut writer).unwrap();

        assert_eq!(writer.into_inner(), qname_bytes("ns1.example.com"));
    }

    #[test]
    fn rdata_ptr_can_be_encoded() {
        let rdata = RData::PTR("host.example.com".to_string());
        let mut writer = wire::Writer::new();

        rdata.encode(&mut writer).unwrap();

        assert_eq!(writer.into_inner(), qname_bytes("host.example.com"));
    }

    #[test]
    fn rdata_mx_can_be_encoded() {
        let rdata = RData::MX {
            preference: 10,
            exchange: "mail.example.com".to_string(),
        };
        let mut writer = wire::Writer::new();

        rdata.encode(&mut writer).unwrap();

        let mut expected = Vec::new();
        push_u16_be(&mut expected, 10);
        expected.extend_from_slice(&qname_bytes("mail.example.com"));

        assert_eq!(writer.into_inner(), expected);
    }

    #[test]
    fn rdata_soa_can_be_encoded() {
        let rdata = RData::SOA {
            mname: "ns1.example.com".to_string(),
            rname: "hostmaster.example.com".to_string(),
            serial: 20240101,
            refresh: 7200,
            retry: 3600,
            expire: 1209600,
            minimum: 3600,
        };
        let mut writer = wire::Writer::new();

        rdata.encode(&mut writer).unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&qname_bytes("ns1.example.com"));
        expected.extend_from_slice(&qname_bytes("hostmaster.example.com"));
        push_u32_be(&mut expected, 20240101);
        push_u32_be(&mut expected, 7200);
        push_u32_be(&mut expected, 3600);
        push_u32_be(&mut expected, 1209600);
        push_u32_be(&mut expected, 3600);

        assert_eq!(writer.into_inner(), expected);
    }

    #[test]
    fn rdata_txt_can_be_encoded() {
        let rdata = RData::TXT(vec![b"hello".to_vec(), b"world".to_vec()]);
        let mut writer = wire::Writer::new();

        rdata.encode(&mut writer).unwrap();

        assert_eq!(
            writer.into_inner(),
            vec![
                5, b'h', b'e', b'l', b'l', b'o', 5, b'w', b'o', b'r', b'l', b'd',
            ]
        );
    }

    #[test]
    fn rdata_txt_empty_list_can_be_encoded() {
        let rdata = RData::TXT(vec![]);
        let mut writer = wire::Writer::new();

        rdata.encode(&mut writer).unwrap();

        assert_eq!(writer.into_inner(), Vec::<u8>::new());
    }

    #[test]
    fn rdata_unknown_can_be_encoded() {
        let rdata = RData::Unknown(vec![0xde, 0xad, 0xbe, 0xef]);
        let mut writer = wire::Writer::new();

        rdata.encode(&mut writer).unwrap();

        assert_eq!(writer.into_inner(), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn rdata_txt_rejects_too_long_string_on_encode() {
        let rdata = RData::TXT(vec![vec![b'a'; 256]]);
        let mut writer = wire::Writer::new();

        let err = rdata.encode(&mut writer).unwrap_err();

        assert_eq!(
            err,
            DnsError::InvalidRdataLength {
                expected: 255,
                actual: 256,
            }
        );
    }

    #[test]
    fn rdata_decode_a_roundtrip() {
        let original = RData::A([93, 184, 216, 34]);

        let mut writer = wire::Writer::new();
        original.encode(&mut writer).unwrap();
        let encoded = writer.into_inner();

        let mut reader = wire::Reader::new(&encoded);
        let decoded = RData::decode(&mut reader, DnsType::A, encoded.len()).unwrap();

        assert_eq!(decoded, original);
    }

    #[test]
    fn rdata_decode_mx_roundtrip() {
        let original = RData::MX {
            preference: 10,
            exchange: "mail.example.com".to_string(),
        };

        let mut writer = wire::Writer::new();
        original.encode(&mut writer).unwrap();
        let encoded = writer.into_inner();

        let mut reader = wire::Reader::new(&encoded);
        let decoded = RData::decode(&mut reader, DnsType::MX, encoded.len()).unwrap();

        assert_eq!(decoded, original);
    }

    #[test]
    fn rdata_decode_txt_roundtrip() {
        let original = RData::TXT(vec![b"hello".to_vec(), b"world".to_vec()]);

        let mut writer = wire::Writer::new();
        original.encode(&mut writer).unwrap();
        let encoded = writer.into_inner();

        let mut reader = wire::Reader::new(&encoded);
        let decoded = RData::decode(&mut reader, DnsType::TXT, encoded.len()).unwrap();

        assert_eq!(decoded, original);
    }
}
