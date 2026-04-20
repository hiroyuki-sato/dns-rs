use crate::dns::error::DnsError;
use crate::dns::name::decode_name;
use crate::dns::records::{DnsClass, DnsType, DomainName, RData, Text};
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
    pub fn decode(reader: &mut wire::Reader, buf: &[u8]) -> Result<Self, DnsError> {
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
