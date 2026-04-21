use crate::dns::error::DnsError;
use crate::dns::name::{decode_name, encode_name_uncompressed};
use crate::dns::records::{DnsClass, DnsType, DomainName};
use crate::wire;

#[derive(Debug, PartialEq, Eq)]
pub struct Question {
    pub qname: DomainName,
    pub qtype: DnsType,
    pub qclass: DnsClass,
}

impl Question {
    pub fn decode(reader: &mut wire::Reader) -> Result<Self, DnsError> {
        // QNAME is a DNS name in wire format.
        let qname = decode_name(reader)?;

        // QTYPE and QCLASS are fixed-width fields after QNAME.
        let qtype = DnsType::from(reader.read_u16_be()?);
        let qclass = DnsClass::from(reader.read_u16_be()?);

        Ok(Question {
            qname,
            qtype,
            qclass,
        })
    }

    pub fn encode(&self, writer: &mut wire::Writer) -> Result<(), DnsError> {
        let enc_qname = encode_name_uncompressed(&self.qname)?;
        writer.write_slice(&enc_qname);
        writer.write_u16_be(self.qtype.into());
        writer.write_u16_be(self.qclass.into());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------
    // Helpers
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

    // ------------------------------------------------------------
    // Decoder tests
    // ------------------------------------------------------------

    #[test]
    fn decode_question_reads_a_question() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&qname_bytes("example.com"));
        push_u16_be(&mut buf, 1); // A
        push_u16_be(&mut buf, 1); // IN

        let mut reader = wire::Reader::new(&buf);

        let question = Question::decode(&mut reader).unwrap();

        assert_eq!(
            question,
            Question {
                qname: "example.com".to_string(),
                qtype: DnsType::A,
                qclass: DnsClass::Internet,
            }
        );
        assert_eq!(reader.position(), buf.len());
    }

    #[test]
    fn decode_question_reads_unknown_type_and_class() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&qname_bytes("example.com"));
        push_u16_be(&mut buf, 65000);
        push_u16_be(&mut buf, 65001);

        let mut reader = wire::Reader::new(&buf);

        let question = Question::decode(&mut reader).unwrap();

        assert_eq!(
            question,
            Question {
                qname: "example.com".to_string(),
                qtype: DnsType::Unknown(65000),
                qclass: DnsClass::Unknown(65001),
            }
        );
    }

    // ------------------------------------------------------------
    // Encoder tests
    // ------------------------------------------------------------

    #[test]
    fn encode_question_writes_a_question() {
        let question = Question {
            qname: "example.com".to_string(),
            qtype: DnsType::A,
            qclass: DnsClass::Internet,
        };

        let mut writer = wire::Writer::new();
        question.encode(&mut writer).unwrap();

        let encoded = writer.into_inner();

        let mut expected = Vec::new();
        expected.extend_from_slice(&qname_bytes("example.com"));
        push_u16_be(&mut expected, 1); // A
        push_u16_be(&mut expected, 1); // IN

        assert_eq!(encoded, expected);
    }

    #[test]
    fn encode_question_writes_unknown_type_and_class() {
        let question = Question {
            qname: "example.com".to_string(),
            qtype: DnsType::Unknown(65000),
            qclass: DnsClass::Unknown(65001),
        };

        let mut writer = wire::Writer::new();
        question.encode(&mut writer).unwrap();

        let encoded = writer.into_inner();

        let mut expected = Vec::new();
        expected.extend_from_slice(&qname_bytes("example.com"));
        push_u16_be(&mut expected, 65000);
        push_u16_be(&mut expected, 65001);

        assert_eq!(encoded, expected);
    }

    #[test]
    fn encode_question_rejects_too_long_label() {
        let question = Question {
            qname: format!("{}.com", "a".repeat(64)),
            qtype: DnsType::A,
            qclass: DnsClass::Internet,
        };

        let mut writer = wire::Writer::new();
        let err = question.encode(&mut writer).unwrap_err();

        assert_eq!(err, DnsError::LabelTooLong);
    }
}
