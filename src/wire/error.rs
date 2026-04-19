#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    UnexpectedEof {
        position: usize,
        needed: usize,
        remaining: usize,
    },
}

impl Error {
    pub const fn unexpected_eof(position: usize, needed: usize, remaining: usize) -> Self {
        Self::UnexpectedEof {
            position,
            needed,
            remaining,
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnexpectedEof {
                position,
                needed,
                remaining,
            } => write!(
                f,
                "unexpected EOF at position {}, needed {} bytes, remaining {} bytes",
                position, needed, remaining
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::Error;

    #[test]
    fn unexpected_eof_constructor() {
        let err = Error::unexpected_eof(10, 4, 2);

        assert_eq!(
            err,
            Error::UnexpectedEof {
                position: 10,
                needed: 4,
                remaining: 2,
            }
        );
    }
    #[test]
    fn display_format() {
        let err = Error::unexpected_eof(10, 4, 2);
        assert_eq!(
            err.to_string(),
            "unexpected EOF at position 10, needed 4 bytes, remaining 2 bytes"
        );
    }
}
