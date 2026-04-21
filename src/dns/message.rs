use crate::dns::error::DnsError;
use crate::dns::question::Question;
use crate::dns::records::{DnsClass, DnsType};
use crate::dns::resource_record::ResourceRecord;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

impl Header {
    pub fn decode(reader: &mut wire::Reader) -> Result<Self, DnsError> {
        let id: u16 = reader.read_u16_be()?;
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

    pub fn encode(&self, writer: &mut wire::Writer) -> Result<(), DnsError> {
        writer.write_u16_be(self.id);

        writer.write_u16_be(self.build_flags());

        writer.write_u16_be(self.qdcount);
        writer.write_u16_be(self.ancount);
        writer.write_u16_be(self.nscount);
        writer.write_u16_be(self.arcount);

        Ok(())
    }

    fn build_flags(&self) -> u16 {
        ((self.qr as u16) << 15)
            | (((self.opcode as u16) & 0x0f) << 11)
            | ((self.aa as u16) << 10)
            | ((self.tc as u16) << 9)
            | ((self.rd as u16) << 8)
            | ((self.ra as u16) << 7)
            | (((self.z as u16) & 0x07) << 4)
            | ((self.rcode as u16) & 0x0f)
    }
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

        let header = Header::decode(&mut reader)?;
        let questions = Self::decode_questions(&mut reader, header.qdcount)?;
        let answers = Self::decode_resource_records(&mut reader, header.ancount)?;
        let authorities = Self::decode_resource_records(&mut reader, header.nscount)?;
        let additionals = Self::decode_resource_records(&mut reader, header.arcount)?;

        Ok(Self {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }

    fn decode_questions(
        reader: &mut wire::Reader<'_>,
        qdcount: u16,
    ) -> Result<Vec<Question>, DnsError> {
        let mut questions = Vec::with_capacity(qdcount as usize);

        // Read exactly qdcount question entries from the current reader position.
        for _ in 0..qdcount {
            let question = Question::decode(reader)?;
            questions.push(question);
        }

        Ok(questions)
    }

    fn decode_resource_records(
        reader: &mut wire::Reader<'_>,
        count: u16,
    ) -> Result<Vec<ResourceRecord>, DnsError> {
        let mut records = Vec::with_capacity(count as usize);

        // Read exactly `count` resource records from the current reader position.
        for _ in 0..count {
            records.push(ResourceRecord::decode(reader)?);
        }

        Ok(records)
    }

    pub fn encode(&self, writer: &mut wire::Writer) -> Result<(), DnsError> {
        // Header counts must match actual sections
        let mut header = self.header;
        header.qdcount = self.questions.len() as u16;
        header.ancount = self.answers.len() as u16;
        header.nscount = self.authorities.len() as u16;
        header.arcount = self.additionals.len() as u16;

        header.encode(writer)?;

        // Questions
        for q in &self.questions {
            q.encode(writer)?;
        }

        // Answers
        for rr in &self.answers {
            rr.encode(writer)?;
        }

        // Authorities
        for rr in &self.authorities {
            rr.encode(writer)?;
        }

        // Additionals
        for rr in &self.additionals {
            rr.encode(writer)?;
        }

        Ok(())
    }

    pub fn new_query(name: &str, qtype: DnsType, recursion: bool) -> Self {
        DnsMessage {
            header: Header {
                id: Self::pseudo_id(),
                qr: false,
                opcode: 0,
                aa: false,
                tc: false,
                rd: recursion,
                ra: false,
                z: 0,
                rcode: 0,
                qdcount: 1,
                ancount: 0,
                nscount: 0,
                arcount: 0,
            },

            questions: vec![Question {
                qname: name.to_string(),
                qtype,
                qclass: DnsClass::Internet,
            }],

            answers: vec![],
            authorities: vec![],
            additionals: vec![],
        }
    }

    fn pseudo_id() -> u16 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();

        (now.subsec_nanos() & 0xffff) as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::dns::rdata::RData;
    use crate::dns::records::{DnsClass, DnsType};

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
        let header = Header::decode(&mut reader).unwrap();

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

        let questions = DnsMessage::decode_questions(&mut reader, 2).unwrap();

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
    // Encoder tests
    // These tests cover only encoding-related behavior.
    // ============================================================

    // ------------------------------------------------------------
    // Header encoder tests
    // ------------------------------------------------------------

    #[test]
    fn encode_header_writes_all_fields() {
        let header = Header {
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
        };

        let mut writer = wire::Writer::new();
        header.encode(&mut writer).unwrap();

        let mut expected = Vec::new();
        push_u16_be(&mut expected, 0x1234);
        push_u16_be(&mut expected, 0x8583);
        push_u16_be(&mut expected, 1);
        push_u16_be(&mut expected, 2);
        push_u16_be(&mut expected, 3);
        push_u16_be(&mut expected, 4);

        assert_eq!(writer.into_inner(), expected);
    }

    #[test]
    fn encode_header_writes_zero_flags() {
        let header = Header {
            id: 0xabcd,
            qr: false,
            opcode: 0,
            aa: false,
            tc: false,
            rd: false,
            ra: false,
            z: 0,
            rcode: 0,
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        };

        let mut writer = wire::Writer::new();
        header.encode(&mut writer).unwrap();

        let mut expected = Vec::new();
        push_u16_be(&mut expected, 0xabcd);
        push_u16_be(&mut expected, 0x0000);
        push_u16_be(&mut expected, 0);
        push_u16_be(&mut expected, 0);
        push_u16_be(&mut expected, 0);
        push_u16_be(&mut expected, 0);

        assert_eq!(writer.into_inner(), expected);
    }

    // ------------------------------------------------------------
    // Full message encoder tests
    // ------------------------------------------------------------

    #[test]
    fn encode_message_with_one_question_and_one_answer() {
        let msg = DnsMessage {
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
        };

        let mut writer = wire::Writer::new();
        msg.encode(&mut writer).unwrap();

        let mut expected = Vec::new();

        // Header
        push_u16_be(&mut expected, 0x1234);
        push_u16_be(&mut expected, 0x8180);
        push_u16_be(&mut expected, 1);
        push_u16_be(&mut expected, 1);
        push_u16_be(&mut expected, 0);
        push_u16_be(&mut expected, 0);

        // Question
        expected.extend_from_slice(&qname_bytes("example.com"));
        push_u16_be(&mut expected, 1);
        push_u16_be(&mut expected, 1);

        // Answer
        expected.extend_from_slice(&qname_bytes("example.com"));
        push_u16_be(&mut expected, 1);
        push_u16_be(&mut expected, 1);
        push_u32_be(&mut expected, 300);
        push_u16_be(&mut expected, 4);
        expected.extend_from_slice(&[93, 184, 216, 34]);

        assert_eq!(writer.into_inner(), expected);
    }

    #[test]
    fn encode_message_overrides_header_counts_from_sections() {
        let msg = DnsMessage {
            header: Header {
                id: 0x1234,
                qr: false,
                opcode: 0,
                aa: false,
                tc: false,
                rd: true,
                ra: false,
                z: 0,
                rcode: 0,
                qdcount: 99,
                ancount: 99,
                nscount: 99,
                arcount: 99,
            },
            questions: vec![Question {
                qname: "example.com".to_string(),
                qtype: DnsType::A,
                qclass: DnsClass::Internet,
            }],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
        };

        let mut writer = wire::Writer::new();
        msg.encode(&mut writer).unwrap();
        let encoded = writer.into_inner();

        assert_eq!(u16::from_be_bytes([encoded[4], encoded[5]]), 1);
        assert_eq!(u16::from_be_bytes([encoded[6], encoded[7]]), 0);
        assert_eq!(u16::from_be_bytes([encoded[8], encoded[9]]), 0);
        assert_eq!(u16::from_be_bytes([encoded[10], encoded[11]]), 0);
    }

    #[test]
    fn encode_then_decode_message_roundtrip() {
        let original = DnsMessage {
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
        };

        let mut writer = wire::Writer::new();
        original.encode(&mut writer).unwrap();
        let encoded = writer.into_inner();

        let decoded = DnsMessage::decode(&encoded).unwrap();

        assert_eq!(decoded, original);
    }

    #[test]
    fn encode_message_with_multiple_sections() {
        let msg = DnsMessage {
            header: Header {
                id: 0x2222,
                qr: true,
                opcode: 0,
                aa: true,
                tc: false,
                rd: true,
                ra: true,
                z: 0,
                rcode: 0,
                qdcount: 1,
                ancount: 1,
                nscount: 1,
                arcount: 1,
            },
            questions: vec![Question {
                qname: "example.com".to_string(),
                qtype: DnsType::NS,
                qclass: DnsClass::Internet,
            }],
            answers: vec![ResourceRecord {
                name: "example.com".to_string(),
                rrtype: DnsType::NS,
                class: DnsClass::Internet,
                ttl: 3600,
                rdata: RData::NS("ns1.example.com".to_string()),
            }],
            authorities: vec![ResourceRecord {
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
            }],
            additionals: vec![ResourceRecord {
                name: "ns1.example.com".to_string(),
                rrtype: DnsType::A,
                class: DnsClass::Internet,
                ttl: 300,
                rdata: RData::A([192, 0, 2, 1]),
            }],
        };

        let mut writer = wire::Writer::new();
        msg.encode(&mut writer).unwrap();
        let encoded = writer.into_inner();

        let decoded = DnsMessage::decode(&encoded).unwrap();

        assert_eq!(decoded, msg);
    }

    // ============================================================
    // End of encoder tests
    // ============================================================
}
