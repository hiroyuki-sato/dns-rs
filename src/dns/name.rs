use crate::dns::error::DnsError;
use crate::wire;

/// Encode a domain name into DNS wire format (uncompressed).
///
/// This function:
/// - Removes a trailing dot (FQDN normalization)
/// - Splits the name into labels by '.'
/// - Encodes each label as: [length][bytes]
/// - Appends a zero-length label (root terminator)
///
/// Example:
/// "www.example.com" -> [3]www[7]example[3]com[0]
///
/// Notes:
/// - This does NOT perform name compression (RFC 1035 section 4.1.4)
/// - Each label must be <= 63 bytes
/// - Total encoded name must be <= 255 bytes
pub fn encode_name_uncompressed(name: &str) -> Result<Vec<u8>, DnsError> {
    // Normalize: remove trailing dot (e.g. "example.com.")
    let name = name.trim_end_matches('.');

    let mut out = Vec::new();
    let mut total_len = 0usize;

    // Root (".") case → just write zero
    if name.is_empty() {
        out.push(0);
        return Ok(out);
    }

    for label in name.split('.') {
        let len = label.len();

        // Each label must be <= 63 bytes
        if len > 63 {
            return Err(DnsError::LabelTooLong);
        }

        // Track total length (including label length byte)
        total_len += 1 + len;

        // Full name must be <= 255 bytes (including final zero)
        if total_len + 1 > 255 {
            return Err(DnsError::NameTooLong);
        }

        out.push(len as u8);
        out.extend_from_slice(label.as_bytes());
    }

    // End of name
    out.push(0);

    Ok(out)
}

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

    // ------------------------------------------------------------
    // Name encoder tests
    // ------------------------------------------------------------

    #[test]
    fn encode_name_uncompressed_basic() {
        let encoded = encode_name_uncompressed("www.example.com").unwrap();

        assert_eq!(
            encoded,
            vec![
                3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o',
                b'm', 0
            ]
        );
    }

    #[test]
    fn encode_name_uncompressed_trailing_dot() {
        let encoded = encode_name_uncompressed("example.com.").unwrap();

        assert_eq!(
            encoded,
            vec![
                7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0
            ]
        );
    }

    #[test]
    fn encode_name_uncompressed_root() {
        let encoded = encode_name_uncompressed(".").unwrap();
        assert_eq!(encoded, vec![0]);
    }

    #[test]
    fn encode_name_uncompressed_single_label() {
        let encoded = encode_name_uncompressed("localhost").unwrap();

        assert_eq!(
            encoded,
            vec![9, b'l', b'o', b'c', b'a', b'l', b'h', b'o', b's', b't', 0]
        );
    }

    #[test]
    fn encode_name_uncompressed_rejects_label_too_long() {
        let long_label = "a".repeat(64);
        let err = encode_name_uncompressed(&long_label).unwrap_err();

        assert_eq!(err, DnsError::LabelTooLong);
    }

    #[test]
    fn encode_name_uncompressed_rejects_name_too_long() {
        // Construct a name slightly over 255 bytes
        let label = "a".repeat(63);
        let name = format!("{}.{}.{}.{}.{}", label, label, label, label, label);

        let err = encode_name_uncompressed(&name).unwrap_err();

        assert_eq!(err, DnsError::NameTooLong);
    }
}
