pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
        }
    }

    pub fn position(&self) -> usize {
        self.buf.len()
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.buf
    }

    pub fn write_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn write_u16_be(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn write_i16_be(&mut self, v: i16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn write_u32_be(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn write_i32_be(&mut self, v: i32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn write_u64_be(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn write_i64_be(&mut self, v: i64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn write_u128_be(&mut self, v: u128) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn write_i128_be(&mut self, v: i128) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn write_array<const N: usize>(&mut self, v: &[u8; N]) {
        self.buf.extend_from_slice(v);
    }

    pub fn write_slice(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }
}

#[cfg(test)]
mod tests {
    use super::Writer;

    #[test]
    fn new_writer_starts_empty() {
        let writer = Writer::new();

        assert_eq!(writer.position(), 0);
        assert_eq!(writer.as_slice(), &[]);
    }

    #[test]
    fn with_capacity_starts_empty() {
        let writer = Writer::with_capacity(128);

        assert_eq!(writer.position(), 0);
        assert_eq!(writer.as_slice(), &[]);
    }

    #[test]
    fn write_u8() {
        let mut writer = Writer::new();

        writer.write_u8(0x12);

        assert_eq!(writer.position(), 1);
        assert_eq!(writer.as_slice(), &[0x12]);
    }

    #[test]
    fn write_u16_be() {
        let mut writer = Writer::new();

        writer.write_u16_be(0x1234);

        assert_eq!(writer.position(), 2);
        assert_eq!(writer.as_slice(), &[0x12, 0x34]);
    }

    #[test]
    fn write_i16_be() {
        let mut writer = Writer::new();

        writer.write_i16_be(-2);

        assert_eq!(writer.position(), 2);
        assert_eq!(writer.as_slice(), &[0xff, 0xfe]);
    }

    #[test]
    fn write_u32_be() {
        let mut writer = Writer::new();

        writer.write_u32_be(0x1234_5678);

        assert_eq!(writer.position(), 4);
        assert_eq!(writer.as_slice(), &[0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn write_i32_be() {
        let mut writer = Writer::new();

        writer.write_i32_be(-2);

        assert_eq!(writer.position(), 4);
        assert_eq!(writer.as_slice(), &[0xff, 0xff, 0xff, 0xfe]);
    }

    #[test]
    fn write_u64_be() {
        let mut writer = Writer::new();

        writer.write_u64_be(0x0123_4567_89ab_cdef);

        assert_eq!(writer.position(), 8);
        assert_eq!(
            writer.as_slice(),
            &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
        );
    }

    #[test]
    fn write_i64_be() {
        let mut writer = Writer::new();

        writer.write_i64_be(-2);

        assert_eq!(writer.position(), 8);
        assert_eq!(
            writer.as_slice(),
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe]
        );
    }

    #[test]
    fn write_u128_be() {
        let mut writer = Writer::new();

        writer.write_u128_be(0x0011_2233_4455_6677_8899_aabb_ccdd_eeff);

        assert_eq!(writer.position(), 16);
        assert_eq!(
            writer.as_slice(),
            &[
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ]
        );
    }

    #[test]
    fn write_i128_be() {
        let mut writer = Writer::new();

        writer.write_i128_be(-2);

        assert_eq!(writer.position(), 16);
        assert_eq!(
            writer.as_slice(),
            &[
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xfe,
            ]
        );
    }

    #[test]
    fn write_array() {
        let mut writer = Writer::new();

        writer.write_array(&[0xde, 0xad, 0xbe, 0xef]);

        assert_eq!(writer.position(), 4);
        assert_eq!(writer.as_slice(), &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn write_slice() {
        let mut writer = Writer::new();

        writer.write_slice(&[0xaa, 0xbb, 0xcc]);

        assert_eq!(writer.position(), 3);
        assert_eq!(writer.as_slice(), &[0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn write_multiple_values_in_sequence() {
        let mut writer = Writer::new();

        writer.write_u8(0x12);
        writer.write_u16_be(0x3456);
        writer.write_u32_be(0x789a_bcde);

        assert_eq!(writer.position(), 7);
        assert_eq!(
            writer.as_slice(),
            &[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde]
        );
    }

    #[test]
    fn into_inner_returns_written_bytes() {
        let mut writer = Writer::new();

        writer.write_u8(0x12);
        writer.write_u16_be(0x3456);

        let buf = writer.into_inner();

        assert_eq!(buf, vec![0x12, 0x34, 0x56]);
    }
}
