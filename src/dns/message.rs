use crate::dns::error::DnsError;
use crate::dns::name::decode_name;
use crate::dns::records::{DnsClass, DnsType, DomainName, Question, RData, ResourceRecord, Text};
use crate::wire;

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
pub struct DnsMessage {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord>,
    pub authorities: Vec<ResourceRecord>,
    pub additionals: Vec<ResourceRecord>,
}

impl DnsMessage {
    pub fn decode(buf: &[u8]) -> Result<Self, DnsError> {
        let mut reader = wire::Reader::new(buf);

        let header = Self::decode_header(&mut reader)?;
        let questions = Self::decode_questions(&mut reader, buf, header.qdcount)?;
        let answers = Self::decode_resource_records(&mut reader, buf, header.ancount)?;
        let authorities = Self::decode_resource_records(&mut reader, buf, header.nscount)?;
        let additionals = Self::decode_resource_records(&mut reader, buf, header.arcount)?;

        Ok(Self {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }

    fn decode_header(reader: &mut wire::Reader<'_>) -> Result<Header, DnsError> {
        let id = reader.read_u16_be()?;
        let flags = reader.read_u16_be()?;

        let qr = (flags & 0x8000) != 0;
        let opcode = ((flags >> 11) & 0x0F) as u8;
        let aa = (flags & 0x0400) != 0;
        let tc = (flags & 0x0200) != 0;
        let rd = (flags & 0x0100) != 0;
        let ra = (flags & 0x0080) != 0;
        let z = ((flags >> 4) & 0x07) as u8;
        let rcode = (flags & 0x000F) as u8;

        let qdcount = reader.read_u16_be()?;
        let ancount = reader.read_u16_be()?;
        let nscount = reader.read_u16_be()?;
        let arcount = reader.read_u16_be()?;

        let header = Header {
            id,
            qr,
            opcode,
            aa,
            tc,
            rd,
            ra,
            z,
            rcode,
            qdcount,
            ancount,
            nscount,
            arcount,
        };

        Ok(header)
    }

    fn decode_questions(
        reader: &mut wire::Reader<'_>,
        buf: &[u8],
        qdcount: u16,
    ) -> Result<Vec<Question>, DnsError> {
        let mut questions = Vec::with_capacity(qdcount as usize);

        // Read exactly qdcount question entries from the current reader position.
        for _ in 0..qdcount {
            // QNAME is a DNS name in wire format.
            let qname = decode_name(reader, buf)?;

            // QTYPE and QCLASS are fixed-width fields after QNAME.
            let qtype = DnsType::from(reader.read_u16_be()?);
            let qclass = DnsClass::from(reader.read_u16_be()?);

            questions.push(Question {
                qname,
                qtype,
                qclass,
            });
        }

        Ok(questions)
    }

    fn decode_resource_records(
        reader: &mut wire::Reader<'_>,
        buf: &[u8],
        count: u16,
    ) -> Result<Vec<ResourceRecord>, DnsError> {
        let mut records = Vec::with_capacity(count as usize);

        // Read exactly `count` resource records from the current reader position.
        for _ in 0..count {
            records.push(Self::decode_resource_record(reader, buf)?);
        }

        Ok(records)
    }

    fn decode_resource_record(
        reader: &mut wire::Reader<'_>,
        buf: &[u8],
    ) -> Result<ResourceRecord, DnsError> {
        // RR NAME may be compressed.
        let name = decode_name(reader, buf)?;

        // Fixed RR header fields.
        let rrtype = DnsType::from(reader.read_u16_be()?);
        let class = DnsClass::from(reader.read_u16_be()?);
        let ttl = reader.read_u32_be()?;
        let rdlength = reader.read_u16_be()? as usize;

        // Decode RDATA based on TYPE.
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
                let cname = Self::decode_name_rdata(reader, buf, rdlength)?;
                RData::CNAME(cname)
            }

            DnsType::NS => {
                let ns = Self::decode_name_rdata(reader, buf, rdlength)?;
                RData::NS(ns)
            }

            DnsType::PTR => {
                let ptr = Self::decode_name_rdata(reader, buf, rdlength)?;
                RData::PTR(ptr)
            }

            DnsType::MX => {
                let start = reader.position();

                let preference = reader.read_u16_be()?;
                let exchange = decode_name(reader, buf)?;

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

                let mname = decode_name(reader, buf)?;
                let rname = decode_name(reader, buf)?;
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

        Ok(ResourceRecord {
            name,
            rrtype,
            class,
            ttl,
            rdata,
        })
    }

    fn decode_name_rdata(
        reader: &mut wire::Reader<'_>,
        buf: &[u8],
        rdlength: usize,
    ) -> Result<DomainName, DnsError> {
        let start = reader.position();

        let name = decode_name(reader, buf)?;

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
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================================
    // Decoder tests
    //
    // These tests cover only decoding-related behavior.
    // Encoding tests should be added below this section later.
    // ============================================================

    // ------------------------------------------------------------
    // Helpers for decoder tests
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
    // Header decoder tests
    // ------------------------------------------------------------

    #[test]
    fn decode_header_reads_all_fields() {
        let mut buf = Vec::new();

        // ID
        push_u16_be(&mut buf, 0x1234);

        // Flags:
        // QR=1, Opcode=0, AA=1, TC=0, RD=1, RA=1, Z=0, RCODE=3
        push_u16_be(&mut buf, 0x8583);

        // QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
        push_u16_be(&mut buf, 1);
        push_u16_be(&mut buf, 2);
        push_u16_be(&mut buf, 3);
        push_u16_be(&mut buf, 4);

        let mut reader = wire::Reader::new(&buf);
        let header = DnsMessage::decode_header(&mut reader).unwrap();

        assert_eq!(
            header,
            Header {
                id: 0x1234,
                qr: true,
                opcode: 0,
                aa: true,
                tc: false,
                rd: true,
                ra: true,
                z: 0,
                rcode: 3,
                qdcount: 1,
                ancount: 2,
                nscount: 3,
                arcount: 4,
            }
        );
    }

    // ------------------------------------------------------------
    // Question decoder tests
    // ------------------------------------------------------------

    #[test]
    fn decode_questions_reads_multiple_questions() {
        let mut buf = Vec::new();

        buf.extend_from_slice(&qname_bytes("example.com"));
        push_u16_be(&mut buf, 1); // A
        push_u16_be(&mut buf, 1); // IN

        buf.extend_from_slice(&qname_bytes("example.net"));
        push_u16_be(&mut buf, 28); // AAAA
        push_u16_be(&mut buf, 1); // IN

        let mut reader = wire::Reader::new(&buf);

        let questions = DnsMessage::decode_questions(&mut reader, &buf, 2).unwrap();

        assert_eq!(
            questions,
            vec![
                Question {
                    qname: "example.com".to_string(),
                    qtype: DnsType::A,
                    qclass: DnsClass::Internet,
                },
                Question {
                    qname: "example.net".to_string(),
                    qtype: DnsType::AAAA,
                    qclass: DnsClass::Internet,
                }
            ]
        );
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

        let rr = DnsMessage::decode_resource_record(&mut reader, &buf).unwrap();

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

        let rr = DnsMessage::decode_resource_record(&mut reader, &buf).unwrap();

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

        let rr = DnsMessage::decode_resource_record(&mut reader, &buf).unwrap();

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

        let rr = DnsMessage::decode_resource_record(&mut reader, &buf).unwrap();

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

        let rr = DnsMessage::decode_resource_record(&mut reader, &buf).unwrap();

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

        let rr = DnsMessage::decode_resource_record(&mut reader, &buf).unwrap();

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

        let rr = DnsMessage::decode_resource_record(&mut reader, &buf).unwrap();

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

        let rr = DnsMessage::decode_resource_record(&mut reader, &buf).unwrap();

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

        let rr = DnsMessage::decode_resource_record(&mut reader, &buf).unwrap();

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

        let err = DnsMessage::decode_resource_record(&mut reader, &buf).unwrap_err();

        assert_eq!(
            err,
            DnsError::InvalidRdataLength {
                expected: 4,
                actual: 3,
            }
        );
    }

    // ------------------------------------------------------------
    // Full message decoder tests
    // ------------------------------------------------------------

    #[test]
    fn decode_message_with_one_question_and_one_answer() {
        let mut buf = Vec::new();

        // Header
        push_u16_be(&mut buf, 0x1234); // ID
        push_u16_be(&mut buf, 0x8180); // standard response, RD+RA, NOERROR
        push_u16_be(&mut buf, 1); // QDCOUNT
        push_u16_be(&mut buf, 1); // ANCOUNT
        push_u16_be(&mut buf, 0); // NSCOUNT
        push_u16_be(&mut buf, 0); // ARCOUNT

        // Question
        buf.extend_from_slice(&qname_bytes("example.com"));
        push_u16_be(&mut buf, 1); // QTYPE A
        push_u16_be(&mut buf, 1); // QCLASS IN

        // Answer
        buf.extend_from_slice(&qname_bytes("example.com"));
        push_u16_be(&mut buf, 1); // TYPE A
        push_u16_be(&mut buf, 1); // CLASS IN
        push_u32_be(&mut buf, 300);
        push_u16_be(&mut buf, 4);
        buf.extend_from_slice(&[93, 184, 216, 34]);

        let msg = DnsMessage::decode(&buf).unwrap();

        assert_eq!(
            msg,
            DnsMessage {
                header: Header {
                    id: 0x1234,
                    qr: true,
                    opcode: 0,
                    aa: false,
                    tc: false,
                    rd: true,
                    ra: true,
                    z: 0,
                    rcode: 0,
                    qdcount: 1,
                    ancount: 1,
                    nscount: 0,
                    arcount: 0,
                },
                questions: vec![Question {
                    qname: "example.com".to_string(),
                    qtype: DnsType::A,
                    qclass: DnsClass::Internet,
                }],
                answers: vec![ResourceRecord {
                    name: "example.com".to_string(),
                    rrtype: DnsType::A,
                    class: DnsClass::Internet,
                    ttl: 300,
                    rdata: RData::A([93, 184, 216, 34]),
                }],
                authorities: vec![],
                additionals: vec![],
            }
        );
    }

    // ============================================================
    // End of decoder tests
    // Encoding tests should be added below this line later.
    // ============================================================
}
