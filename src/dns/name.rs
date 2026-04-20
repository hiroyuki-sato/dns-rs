use crate::dns::error::DnsError;
use crate::wire;

/// Decode a DNS name from the current reader position.
///
/// This is a small public wrapper that initializes state used for
/// compression-pointer safety checks.
///
/// RFC 1035 name compression:
/// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
pub fn decode_name(reader: &mut wire::Reader<'_>) -> Result<String, DnsError> {
    let mut visited_offsets = Vec::new();
    decode_name_inner(reader, &mut visited_offsets, 0)
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

            let buf = reader.buf();

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

            let suffix = decode_name_inner(&mut jump_reader, visited_offsets, jump_count + 1)?;

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

#[cfg(test)]
mod test {
    use super::*;

    // ------------------------------------------------------------
    // Test helpers for name decoder tests
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

    // ------------------------------------------------------------
    // Name decoder tests
    // ------------------------------------------------------------

    #[test]
    fn decode_name_reads_uncompressed_name() {
        let buf = qname_bytes("www.example.com");
        let mut reader = wire::Reader::new(&buf);

        let name = decode_name(&mut reader).unwrap();

        assert_eq!(name, "www.example.com");
        assert_eq!(reader.position(), buf.len());
    }

    #[test]
    fn decode_name_reads_compressed_name() {
        let mut buf = Vec::new();

        // Offset 0: "example.com"
        let example_offset = buf.len();
        buf.extend_from_slice(&qname_bytes("example.com"));

        // Then: "www" + pointer to example.com at offset 0
        let compressed_start = buf.len();
        buf.push(3);
        buf.extend_from_slice(b"www");
        buf.push(0xC0);
        buf.push(example_offset as u8);

        let mut reader = wire::Reader::at(&buf, compressed_start);

        let name = decode_name(&mut reader).unwrap();

        assert_eq!(name, "www.example.com");
        assert_eq!(reader.position(), 19);
    }

    #[test]
    fn decode_name_rejects_pointer_out_of_bounds() {
        let buf = vec![0xC0, 0xFF];
        let mut reader = wire::Reader::new(&buf);

        let err = decode_name(&mut reader).unwrap_err();

        assert_eq!(err, DnsError::PointerOutOfBounds);
    }

    #[test]
    fn decode_name_rejects_compression_loop() {
        let buf = vec![0xC0, 0x00];
        let mut reader = wire::Reader::new(&buf);

        let err = decode_name(&mut reader).unwrap_err();

        assert_eq!(err, DnsError::CompressionLoop);
    }
}
