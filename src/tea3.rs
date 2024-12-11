#[rustfmt::skip]
pub const S: [u8; 256] = [
    0x7D, 0xBF, 0x7B, 0x92, 0xAE, 0x7C, 0xF2, 0x10, 0x5A, 0x0F, 0x61, 0x7A, 0x98, 0x76, 0x07, 0x64,
    0xEE, 0x89, 0xF7, 0xBA, 0xC2, 0x02, 0x0D, 0xE8, 0x56, 0x2E, 0xCA, 0x58, 0xC0, 0xFA, 0x2A, 0x01,
    0x57, 0x6E, 0x3F, 0x4B, 0x9C, 0xDA, 0xA6, 0x5B, 0x41, 0x26, 0x50, 0x24, 0x3E, 0xF8, 0x0A, 0x86,
    0xB6, 0x5C, 0x34, 0xE9, 0x06, 0x88, 0x1F, 0x39, 0x33, 0xDF, 0xD9, 0x78, 0xD8, 0xA8, 0x51, 0xB2,
    0x09, 0xCD, 0xA1, 0xDD, 0x8E, 0x62, 0x69, 0x4D, 0x23, 0x2B, 0xA9, 0xE1, 0x53, 0x94, 0x90, 0x1E,
    0xB4, 0x3B, 0xF9, 0x4E, 0x36, 0xFE, 0xB5, 0xD1, 0xA2, 0x8D, 0x66, 0xCE, 0xB7, 0xC4, 0x60, 0xED,
    0x96, 0x4F, 0x31, 0x79, 0x35, 0xEB, 0x8F, 0xBB, 0x54, 0x14, 0xCB, 0xDE, 0x6B, 0x2D, 0x19, 0x82,
    0x80, 0xAC, 0x17, 0x05, 0xFF, 0xA4, 0xCF, 0xC6, 0x6F, 0x65, 0xE6, 0x74, 0xC8, 0x93, 0xF4, 0x7E,
    0xF3, 0x43, 0x9F, 0x71, 0xAB, 0x9A, 0x0B, 0x87, 0x55, 0x70, 0x0C, 0xAD, 0xCC, 0xA5, 0x44, 0xE7,
    0x46, 0x45, 0x03, 0x30, 0x1A, 0xEA, 0x67, 0x99, 0xDB, 0x4A, 0x42, 0xD7, 0xAA, 0xE4, 0xC2, 0xD5,
    0xF0, 0x77, 0x20, 0xC3, 0x3C, 0x16, 0xB9, 0xE2, 0xEF, 0x6C, 0x3D, 0x1B, 0x22, 0x84, 0x2F, 0x81,
    0x1D, 0xB1, 0x3A, 0xE5, 0x73, 0x40, 0xD0, 0x18, 0xC7, 0x6A, 0x9E, 0x91, 0x48, 0x27, 0x95, 0x72,
    0x68, 0x0E, 0x00, 0xFC, 0xC5, 0x5F, 0xF1, 0xF5, 0x38, 0x11, 0x7F, 0xE3, 0x5E, 0x13, 0xAF, 0x37,
    0xE0, 0x8A, 0x49, 0x1C, 0x21, 0x47, 0xD4, 0xDC, 0xB0, 0xEC, 0x83, 0x28, 0xB8, 0xF6, 0xA7, 0xC9,
    0x63, 0x59, 0xBD, 0x32, 0x85, 0x08, 0xBE, 0xD3, 0xFD, 0x4C, 0x2C, 0xFB, 0xA0, 0xC1, 0x9D, 0xB3,
    0x52, 0x8C, 0x5D, 0x29, 0x6D, 0x04, 0xBC, 0x25, 0x15, 0x8B, 0x12, 0x9B, 0xD6, 0x75, 0xA3, 0x97
];

fn b_permute(x: u8) -> u8 {
    ((x & 0x00000010) << 1)
        | ((x & 0x00000026) << 2)
        | ((x & 0x00000001) << 6)
        | ((x & 0x00000080) >> 6)
        | ((x & 0x00000040) >> 4)
        | ((x & 0x00000008) >> 3)
}

// 8 S-boxes thare map 4-bits to 1-bit
const LUT_A: [u16; 8] = [
    0x92A7, 0xA761, 0x974C, 0x6B8C, 0x29CE, 0x176C, 0x39D4, 0x7463,
];
const LUT_B: [u16; 8] = [
    0x9D58, 0xA46D, 0x176C, 0x79C4, 0xC62B, 0xB2C9, 0x4D93, 0x2E93,
];

// TODO: change name
fn f_function(a: [u8; 2], sboxes: &[u16; 8]) -> u8 {
    let mut a0 = a[0];
    let mut a1 = a[1];

    let mut output: u8 = 0;

    for (sbox_number, sbox) in sboxes.iter().enumerate() {
        // We take 2 bits from each of a0 and a1, concatenate them, and interpret that as the
        // index into the S-box. We take bit 5 and 6 and move the window left on each iteration.
        // In practice we rotate the value right, but it is equivalent.
        let sbox_index = ((a1 >> 5) & 0b11) | ((a0 >> 3) & 0b1100);

        let output_bit = (sbox >> sbox_index) & 1;
        let output_bit = output_bit as u8;
        output |= output_bit << sbox_number;

        // rotate one position
        a0 = a0.rotate_right(1);
        a1 = a1.rotate_right(1);
    }

    output
}

#[derive(Debug)]
struct Tea3 {
    state_register: [u8; 8],
    key_register: [u8; 10],
}

impl Tea3 {
    fn new(iv: u32, key: [u8; 10]) -> Self {
        let xored = iv ^ 0xC43A7D51;
        let xored = xored.rotate_left(8);
        let iv: u64 = (iv as u64) << 32 | xored as u64;
        let iv = iv.rotate_right(8);

        Self {
            state_register: iv.to_be_bytes(),
            key_register: key,
        }
    }

    fn clock(&mut self) -> u8 {
        let output = self.state_register[0];

        let new_key_word =
            self.key_register[0] ^ S[(self.key_register[2] ^ self.key_register[7]) as usize];

        let b = b_permute(self.state_register[3]);
        let f1 = f_function(self.state_register[5..=6].try_into().unwrap(), &LUT_A);
        let new_state_word = b ^ f1 ^ self.state_register[0] ^ new_key_word;

        let f2 = f_function(self.state_register[1..=2].try_into().unwrap(), &LUT_B);

        // After the clock R2
        self.state_register[3] ^= f2;
        self.state_register.rotate_left(1);
        self.state_register[7] = new_state_word;

        self.key_register.rotate_left(1);
        self.key_register[9] = new_key_word;

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doesnt_panic() {
        for i in 0..=0xff_u8 {
            b_permute(i);
        }
        for i in 0..=0xff_ff_u16 {
            f_function(i.to_le_bytes(), &LUT_A);
            f_function(i.to_le_bytes(), &LUT_B);
        }
    }

    #[test]
    fn test_vector_with_zero_iv() {
        let expected_output: &[u8] = &[
            196, 0, 0, 242, 59, 102, 81, 215, 101, 145, 247, 1, 138, 222, 94, 190, 156, 31, 33,
            145, 212, 9, 92, 35, 141, 61, 237, 214, 139, 255, 29, 170, 41, 242, 230, 227, 150, 88,
            42, 219, 154, 5, 88, 232, 119, 19, 81, 142, 183, 23, 154, 180, 253, 169, 146, 219, 165,
            56, 136, 68, 2, 204, 98, 75, 12, 50, 143, 51, 104, 86, 218, 53, 213, 145, 72, 157, 226,
            12, 45, 89, 29, 77, 174, 226, 157, 185, 41, 225, 192, 203, 97, 24, 59, 174, 197, 27,
            60, 212, 169, 172, 62, 89, 200, 183, 19, 169, 27, 161, 60, 45, 235, 246, 46, 192, 202,
            51, 160, 132, 175, 227, 90, 155, 143, 239, 184, 59, 45, 151, 169, 46, 34, 96, 204, 134,
            117, 234, 98, 81, 125, 166, 28, 63, 106, 126, 210, 25, 122, 104, 70, 80, 44, 181, 137,
            38, 106, 246, 183, 118, 102, 33, 142, 87, 11, 244, 247, 216, 60, 199, 145, 235, 190,
            198, 230, 28, 74, 205, 184, 123, 71, 125, 161, 62, 103, 49, 106, 110, 116, 222, 224,
            24, 199, 17, 125, 66, 109, 23, 16, 194, 116, 200, 202, 192, 125, 82, 33, 92, 161, 101,
            233, 175, 193, 40, 17, 75, 8, 99, 173, 173, 234, 0, 201, 143,
        ];

        let key = [229, 124, 168, 23, 230, 39, 190, 106, 213, 36];
        let mut cipher = Tea3::new(0, key);

        for (i, expected_word) in expected_output.iter().enumerate() {
            let output = cipher.clock();
            dbg!(i, expected_word, output);
            assert_eq!(output, *expected_word, "incongruence at i = {i}");
        }
    }

    #[test]
    fn test_initialization() {
        let expected_register_state = 0xc4000000003a7d51_u64.to_be_bytes();
        let key = [229, 124, 168, 23, 230, 39, 190, 106, 213, 36];
        let cipher = Tea3::new(0, key);
        assert_eq!(cipher.state_register, expected_register_state);
    }
}
