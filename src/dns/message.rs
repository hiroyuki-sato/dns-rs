use crate::dns::error::DnsError;
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

pub struct Question {
    pub qname: DomainName,
    pub qtype: DnsType,
    pub qclass: DnsClass,
}

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRecord {
    pub name: DomainName,
    pub rrtype: DnsType,
    pub class: DnsClass,
    pub ttl: u32,
    pub rdata: RData,
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
            let qname = Self::decode_name(reader, buf)?;

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
    /// Decode a DNS name from the current reader position.
    ///
    /// This is a small public wrapper that initializes state used for
    /// compression-pointer safety checks.
    ///
    /// RFC 1035 name compression:
    /// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
    pub fn decode_name(reader: &mut wire::Reader<'_>, buf: &[u8]) -> Result<String, DnsError> {
        let mut visited_offsets = Vec::new();
        Self::decode_name_inner(reader, buf, &mut visited_offsets, 0)
    }

    /// Internal DNS name decoder.
    ///
    /// Handles:
    /// - normal labels
    /// - zero terminator
    /// - compression pointers
    /// - pointer loop detection
    /// - pointer bounds checks
    ///
    /// `visited_offsets` tracks pointer targets already followed.
    /// `jump_count` limits how many pointers we follow.
    fn decode_name_inner(
        reader: &mut wire::Reader<'_>,
        buf: &[u8],
        visited_offsets: &mut Vec<usize>,
        jump_count: usize,
    ) -> Result<String, DnsError> {
        const MAX_POINTER_JUMPS: usize = 16;

        // Prevent excessive or malicious pointer chains.
        if jump_count >= MAX_POINTER_JUMPS {
            return Err(DnsError::CompressionLoop);
        }

        let mut labels = Vec::new();
        let mut total_name_len = 0usize;

        loop {
            let len = reader.read_u8()?;

            // Zero length means end of name.
            if len == 0 {
                break;
            }

            // Top two bits set means this is a compression pointer.
            if (len & 0xC0) == 0xC0 {
                let b2 = reader.read_u8()?;
                let offset = ((((len & 0x3F) as u16) << 8) | b2 as u16) as usize;

                // Pointer must refer to a valid position inside the message.
                if offset >= buf.len() {
                    return Err(DnsError::PointerOutOfBounds);
                }

                // Detect pointer loops like A -> B -> A.
                if visited_offsets.contains(&offset) {
                    return Err(DnsError::CompressionLoop);
                }

                visited_offsets.push(offset);

                // Follow the pointer using a fresh reader rooted at the full buffer.
                let mut jump_reader = wire::Reader::new(&buf[offset..]);

                let suffix = Self::decode_name_inner(
                    &mut jump_reader,
                    buf,
                    visited_offsets,
                    jump_count + 1,
                )?;

                labels.push(suffix);

                // A compression pointer terminates the current name.
                break;
            }

            // Normal label: top two bits must be zero.
            if (len & 0xC0) != 0x00 {
                return Err(DnsError::InvalidLabelLength(len));
            }

            let label_len = len as usize;

            // RFC label size limit is 63 bytes.
            if label_len > 63 {
                return Err(DnsError::LabelTooLong);
            }

            let label_bytes = reader.read_slice(label_len)?;

            // For this implementation we assume UTF-8 labels.
            let label = core::str::from_utf8(label_bytes)
                .map_err(|_| DnsError::InvalidLabelLength(len))?
                .to_string();

            total_name_len += label_len;
            if !labels.is_empty() {
                total_name_len += 1; // account for '.'
            }

            // RFC full name size limit is 255 octets.
            if total_name_len > 255 {
                return Err(DnsError::NameTooLong);
            }

            labels.push(label);
        }

        Ok(labels.join("."))
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
        let name = Self::decode_name(reader, buf)?;

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
                let exchange = Self::decode_name(reader, buf)?;

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

                let mname = Self::decode_name(reader, buf)?;
                let rname = Self::decode_name(reader, buf)?;
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

        let name = Self::decode_name(reader, buf)?;

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
