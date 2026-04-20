use crate::dns::error::DnsError;
use crate::dns::name::decode_name;
use crate::dns::records::{DnsClass, DnsType, DomainName};
use crate::wire;

#[derive(Debug, PartialEq, Eq)]
pub struct Question {
    pub qname: DomainName,
    pub qtype: DnsType,
    pub qclass: DnsClass,
}

impl Question {
    pub fn decode(reader: &mut wire::Reader, buf: &[u8]) -> Result<Self, DnsError> {
        // QNAME is a DNS name in wire format.
        let qname = decode_name(reader, buf)?;

        // QTYPE and QCLASS are fixed-width fields after QNAME.
        let qtype = DnsType::from(reader.read_u16_be()?);
        let qclass = DnsClass::from(reader.read_u16_be()?);

        Ok(Question {
            qname,
            qtype,
            qclass,
        })
    }
}
