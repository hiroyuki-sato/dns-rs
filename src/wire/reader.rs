use crate::wire::error::Error;

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.remaining() < n {
            return Err(Error::unexpected_eof(self.pos, n, self.remaining()));
        }
        let start = self.pos;
        self.pos += n;
        Ok(&self.buf[start..start + n])
    }

    pub fn read_u8(&mut self) -> Result<u8, Error> {
        let bytes = self.take(1)?;
        Ok(bytes[0])
    }

    pub fn read_u16_be(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    pub fn read_i16_be(&mut self) -> Result<i16, Error> {
        Ok(i16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    pub fn read_u32_be(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    pub fn read_i32_be(&mut self) -> Result<i32, Error> {
        Ok(i32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    pub fn read_u64_be(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    pub fn read_i64_be(&mut self) -> Result<i64, Error> {
        Ok(i64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    pub fn read_u128_be(&mut self) -> Result<u128, Error> {
        Ok(u128::from_be_bytes(self.take(16)?.try_into().unwrap()))
    }

    pub fn read_i128_be(&mut self) -> Result<i128, Error> {
        Ok(i128::from_be_bytes(self.take(16)?.try_into().unwrap()))
    }

    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        Ok(self.take(N)?.try_into().unwrap())
    }
    pub fn read_slice(&mut self, n: usize) -> Result<&'a [u8], Error> {
        self.take(n)
    }
}

#[cfg(test)]
mod tests {
    use super::Reader;
    use crate::wire::error::Error;

    #[test]
    fn new_reader_starts_at_position_zero() {
        let reader = Reader::new(&[0x00, 0x01, 0x02]);

        assert_eq!(reader.position(), 0);
        assert_eq!(reader.remaining(), 3);
    }

    #[test]
    fn read_u8_advances_position() {
        let mut reader = Reader::new(&[0x12, 0x34]);

        assert_eq!(reader.read_u8().unwrap(), 0x12);
        assert_eq!(reader.position(), 1);
        assert_eq!(reader.remaining(), 1);
    }

    #[test]
    fn read_u16_be() {
        let mut reader = Reader::new(&[0x12, 0x34]);

        assert_eq!(reader.read_u16_be().unwrap(), 0x1234);
        assert_eq!(reader.position(), 2);
        assert_eq!(reader.remaining(), 0);
    }

    #[test]
    fn read_i16_be() {
        let mut reader = Reader::new(&[0xff, 0xfe]);

        assert_eq!(reader.read_i16_be().unwrap(), -2);
        assert_eq!(reader.position(), 2);
        assert_eq!(reader.remaining(), 0);
    }

    #[test]
    fn read_u32_be() {
        let mut reader = Reader::new(&[0x12, 0x34, 0x56, 0x78]);

        assert_eq!(reader.read_u32_be().unwrap(), 0x1234_5678);
        assert_eq!(reader.position(), 4);
        assert_eq!(reader.remaining(), 0);
    }

    #[test]
    fn read_i32_be() {
        let mut reader = Reader::new(&[0xff, 0xff, 0xff, 0xfe]);

        assert_eq!(reader.read_i32_be().unwrap(), -2);
        assert_eq!(reader.position(), 4);
        assert_eq!(reader.remaining(), 0);
    }

    #[test]
    fn read_u64_be() {
        let mut reader = Reader::new(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);

        assert_eq!(reader.read_u64_be().unwrap(), 0x0123_4567_89ab_cdef);
        assert_eq!(reader.position(), 8);
        assert_eq!(reader.remaining(), 0);
    }

    #[test]
    fn read_i64_be() {
        let mut reader = Reader::new(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe]);

        assert_eq!(reader.read_i64_be().unwrap(), -2);
        assert_eq!(reader.position(), 8);
        assert_eq!(reader.remaining(), 0);
    }

    #[test]
    fn read_u128_be() {
        let mut reader = Reader::new(&[
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ]);

        assert_eq!(
            reader.read_u128_be().unwrap(),
            0x0011_2233_4455_6677_8899_aabb_ccdd_eeff
        );
        assert_eq!(reader.position(), 16);
        assert_eq!(reader.remaining(), 0);
    }

    #[test]
    fn read_i128_be() {
        let mut reader = Reader::new(&[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe,
        ]);

        assert_eq!(reader.read_i128_be().unwrap(), -2);
        assert_eq!(reader.position(), 16);
        assert_eq!(reader.remaining(), 0);
    }

    #[test]
    fn read_array() {
        let mut reader = Reader::new(&[0xde, 0xad, 0xbe, 0xef, 0x12]);

        assert_eq!(reader.read_array::<4>().unwrap(), [0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(reader.position(), 4);
        assert_eq!(reader.remaining(), 1);
    }

    #[test]
    fn read_multiple_values_in_sequence() {
        let mut reader = Reader::new(&[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde]);

        assert_eq!(reader.read_u8().unwrap(), 0x12);
        assert_eq!(reader.read_u16_be().unwrap(), 0x3456);
        assert_eq!(reader.read_u32_be().unwrap(), 0x789a_bcde);
        assert_eq!(reader.position(), 7);
        assert_eq!(reader.remaining(), 0);
    }

    #[test]
    fn read_u8_returns_unexpected_eof() {
        let mut reader = Reader::new(&[]);

        let err = reader.read_u8().unwrap_err();

        assert_eq!(
            err,
            Error::UnexpectedEof {
                position: 0,
                needed: 1,
                remaining: 0,
            }
        );
    }

    #[test]
    fn read_u16_be_returns_unexpected_eof() {
        let mut reader = Reader::new(&[0x12]);

        let err = reader.read_u16_be().unwrap_err();

        assert_eq!(
            err,
            Error::UnexpectedEof {
                position: 0,
                needed: 2,
                remaining: 1,
            }
        );
    }

    #[test]
    fn read_after_partial_consumption_returns_unexpected_eof() {
        let mut reader = Reader::new(&[0x12, 0x34, 0x56]);

        assert_eq!(reader.read_u8().unwrap(), 0x12);

        let err = reader.read_u32_be().unwrap_err();

        assert_eq!(
            err,
            Error::UnexpectedEof {
                position: 1,
                needed: 4,
                remaining: 2,
            }
        );
    }

    #[test]
    fn read_array_returns_unexpected_eof() {
        let mut reader = Reader::new(&[0xaa, 0xbb, 0xcc]);

        let err = reader.read_array::<4>().unwrap_err();

        assert_eq!(
            err,
            Error::UnexpectedEof {
                position: 0,
                needed: 4,
                remaining: 3,
            }
        );
    }

    #[cfg(test)]
    mod tests {
        use super::Reader;
        use crate::wire::Error;

        #[test]
        fn read_slice_reads_exact_bytes() {
            let buf = [1, 2, 3, 4, 5];
            let mut reader = Reader::new(&buf);

            let slice = reader.read_slice(3).unwrap();

            assert_eq!(slice, &[1, 2, 3]);
            assert_eq!(reader.position(), 3);
            assert_eq!(reader.remaining(), 2);
        }

        #[test]
        fn read_slice_reads_all_remaining() {
            let buf = [10, 20, 30];
            let mut reader = Reader::new(&buf);

            let slice = reader.read_slice(3).unwrap();

            assert_eq!(slice, &[10, 20, 30]);
            assert_eq!(reader.position(), 3);
            assert_eq!(reader.remaining(), 0);
        }

        #[test]
        fn read_slice_multiple_reads() {
            let buf = [1, 2, 3, 4];
            let mut reader = Reader::new(&buf);

            let a = reader.read_slice(2).unwrap();
            let b = reader.read_slice(2).unwrap();

            assert_eq!(a, &[1, 2]);
            assert_eq!(b, &[3, 4]);
            assert_eq!(reader.remaining(), 0);
        }

        #[test]
        fn read_slice_zero_length() {
            let buf = [1, 2, 3];
            let mut reader = Reader::new(&buf);

            let slice = reader.read_slice(0).unwrap();

            assert_eq!(slice, &[]);
            assert_eq!(reader.position(), 0);
            assert_eq!(reader.remaining(), 3);
        }

        #[test]
        fn read_slice_returns_error_when_not_enough_bytes() {
            let buf = [1, 2];
            let mut reader = Reader::new(&buf);

            let err = reader.read_slice(3).unwrap_err();

            assert_eq!(
                err,
                Error::UnexpectedEof {
                    position: 0,
                    needed: 3,
                    remaining: 2,
                }
            );
        }

        #[test]
        fn read_slice_error_does_not_advance_position() {
            let buf = [1, 2];
            let mut reader = Reader::new(&buf);

            let _ = reader.read_slice(3);

            assert_eq!(reader.position(), 0);
            assert_eq!(reader.remaining(), 2);
        }
    }
}
