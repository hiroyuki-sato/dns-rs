use crate::wire;

#[derive(Debug, PartialEq, Eq)]
pub enum DnsError {
    Wire(wire::Error),
    InvalidHeader,
    InvalidLabelLength(u8),
    LabelTooLong,
    NameTooLong,
    CompressionLoop,
    PointerOutOfBounds,
    InvalidRdataLength { expected: usize, actual: usize },
    UnsupportedType(u16),
}

impl From<wire::Error> for DnsError {
    fn from(err: wire::Error) -> Self {
        Self::Wire(err)
    }
}

impl core::fmt::Display for DnsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DnsError::Wire(err) => write!(f, "wire error: {}", err),
            DnsError::InvalidHeader => write!(f, "invalid header"),
            DnsError::InvalidLabelLength(l) => write!(f, "invalid label length: {}", l),
            DnsError::LabelTooLong => write!(f, "label too long"),
            DnsError::NameTooLong => write!(f, "name too long"),
            DnsError::CompressionLoop => write!(f, "compression loop"),
            DnsError::PointerOutOfBounds => write!(f, "pointer out of bounds"),
            DnsError::InvalidRdataLength { expected, actual } => {
                write!(
                    f,
                    "invalid rdata length: expected {}, actual {}",
                    expected, actual
                )
            }
            DnsError::UnsupportedType(t) => write!(f, "unsupported type: {}", t),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_invalid_header() {
        let err = DnsError::InvalidHeader;
        assert_eq!(err.to_string(), "invalid header");
    }

    #[test]
    fn display_invalid_label_length() {
        let err = DnsError::InvalidLabelLength(64);
        assert_eq!(err.to_string(), "invalid label length: 64");
    }

    #[test]
    fn display_label_too_long() {
        let err = DnsError::LabelTooLong;
        assert_eq!(err.to_string(), "label too long");
    }

    #[test]
    fn display_name_too_long() {
        let err = DnsError::NameTooLong;
        assert_eq!(err.to_string(), "name too long");
    }

    #[test]
    fn display_compression_loop() {
        let err = DnsError::CompressionLoop;
        assert_eq!(err.to_string(), "compression loop");
    }

    #[test]
    fn display_pointer_out_of_bounds() {
        let err = DnsError::PointerOutOfBounds;
        assert_eq!(err.to_string(), "pointer out of bounds");
    }

    #[test]
    fn display_invalid_rdata_length() {
        let err = DnsError::InvalidRdataLength {
            expected: 4,
            actual: 3,
        };
        assert_eq!(
            err.to_string(),
            "invalid rdata length: expected 4, actual 3"
        );
    }

    #[test]
    fn display_unsupported_type() {
        let err = DnsError::UnsupportedType(28);
        assert_eq!(err.to_string(), "unsupported type: 28");
    }

    #[test]
    fn from_wire_error() {
        let wire_err = wire::Error::UnexpectedEof {
            position: 10,
            needed: 2,
            remaining: 0,
        };

        let dns_err: DnsError = wire_err.into();

        match dns_err {
            DnsError::Wire(wire::Error::UnexpectedEof {
                position,
                needed,
                remaining,
            }) => {
                assert_eq!(position, 10);
                assert_eq!(needed, 2);
                assert_eq!(remaining, 0);
            }
            _ => panic!("expected DnsError::Wire(UnexpectedEof)"),
        }
    }

    #[test]
    fn invalid_rdata_length_equality() {
        let a = DnsError::InvalidRdataLength {
            expected: 16,
            actual: 4,
        };
        let b = DnsError::InvalidRdataLength {
            expected: 16,
            actual: 4,
        };

        assert_eq!(a, b);
    }
}
