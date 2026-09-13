/// The polynomial used for the crc32 lookup table.
///
/// See also https://en.wikipedia.org/wiki/Cyclic_redundancy_check#Polynomial_representations
const POLYNOMIAL: u32 = 0x04C11DB7;

/// Most implementations (ethernet, zlib) use the reflected version of this polynomial.
const _: () = assert!(POLYNOMIAL.reverse_bits() == 0xEDB88320);

/// Lookup table to speed up crc32 checksum calculation.
///
/// The original C implementation notes:
///
/// > I think this is an implementation of the AUTODIN-II,
/// > Ethernet & FDDI 32-bit CRC standard.  Vaguely derived
/// > from code by Rob Warnock, in Section 51 of the
/// > comp.compression FAQ.
pub(crate) static BZ2_CRC32TABLE: [u32; 256] = generate_crc32_table(POLYNOMIAL);

/// Generate the crc32 lookup table.
///
/// Note that contrary to most material you'll find on the internet, we're using the non-reflected
/// polynomial, which impacts some of the logic (e.g. we bitwise and with 0x80000000 instead of 0x1).
///
/// This [article] has some excellent additional detail on how crc works, and how to make it fast.
///
/// [article]: https://create.stephan-brumme.com/crc32/
const fn generate_crc32_table(polynomial: u32) -> [u32; 256] {
    let mut table = [0u32; 256];

    let mut i = 0;
    while i < 256 {
        let mut crc = (i as u32) << 24;

        let mut j = 0;
        while j < 8 {
            if (crc & 0x80000000) != 0 {
                crc = (crc << 1) ^ polynomial;
            } else {
                crc <<= 1;
            }

            j += 1;
        }

        table[i] = crc;

        i += 1;
    }

    table
}

pub(crate) static BZ2_CRC32TABLE_4: [[u32; 256]; 4] = generate_crc32_table_4(POLYNOMIAL);

const fn generate_crc32_table_4(polynomial: u32) -> [[u32; 256]; 4] {
    let mut table = [[0u32; 256]; 4];
    table[0] = generate_crc32_table(polynomial);

    let mut k = 1;
    while k < 4 {
        let mut i = 0;
        while i < 256 {
            let last = table[k - 1][i];
            let index = (last >> 24) as usize;
            table[k][i] = (last << 8) ^ table[0][index];
            i += 1;
        }
        k += 1;
    }

    table
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32_tables() {
        let t1 = generate_crc32_table(POLYNOMIAL);
        assert_eq!(t1, BZ2_CRC32TABLE);
        let t4 = generate_crc32_table_4(POLYNOMIAL);
        assert_eq!(t4, BZ2_CRC32TABLE_4);
    }

    #[test]
    fn test_crc32_slice4_equivalence() {
        for ch in 0..=255u8 {
            for initial_crc in [0u32, 0xFFFFFFFF, 0x12345678, 0xEDB88320] {
                let mut scalar_crc = initial_crc;
                for _ in 0..4 {
                    scalar_crc = (scalar_crc << 8)
                        ^ BZ2_CRC32TABLE[((scalar_crc >> 24) ^ (ch as u32)) as usize];
                }
                let mut slice4_crc = initial_crc;
                let c = slice4_crc ^ ((ch as u32) * 0x01010101);
                slice4_crc = BZ2_CRC32TABLE_4[3][(c >> 24) as usize]
                    ^ BZ2_CRC32TABLE_4[2][((c >> 16) & 0xFF) as usize]
                    ^ BZ2_CRC32TABLE_4[1][((c >> 8) & 0xFF) as usize]
                    ^ BZ2_CRC32TABLE_4[0][(c & 0xFF) as usize];
                assert_eq!(
                    scalar_crc, slice4_crc,
                    "Mismatch for ch={}, crc={:#X}",
                    ch, initial_crc
                );
            }
        }
    }
}
