//! Port of Core's `ecdsa_signature_parse_der_lax` (`src/pubkey.cpp`).
//!
//! Before BIP66 any signature this parser accepts was valid on chain, so
//! `OP_CHECKSIG` must accept the same encodings Core does. Strict DER
//! parsers reject mainnet transactions such as the one at block 124,276,
//! whose `r` and `s` carry redundant leading zero bytes.

/// A signature decoded the way Core's lax DER parser decodes it.
pub struct LaxDer;

impl LaxDer {
    /// Returns the 64-byte compact `r || s`, or `None` when Core's parser
    /// fails or yields a signature that can never verify. Core turns an
    /// out-of-range `r` or `s` into an all-zero signature, which no
    /// verification accepts, so `None` and that case have the same outcome.
    #[must_use]
    pub fn parse(input: &[u8]) -> Option<[u8; 64]> {
        let mut cursor = LaxCursor { input, pos: 0 };
        cursor.expect_byte(0x30)?;
        cursor.skip_sequence_length()?;
        let r = cursor.integer()?;
        let s = cursor.integer()?;

        let mut compact = [0u8; 64];
        LaxDer::copy_right_aligned(r, &mut compact[..32])?;
        LaxDer::copy_right_aligned(s, &mut compact[32..])?;
        Some(compact)
    }

    fn copy_right_aligned(value: &[u8], out: &mut [u8]) -> Option<()> {
        let leading_zeros = value.iter().take_while(|&&b| b == 0).count();
        let magnitude = &value[leading_zeros..];
        if magnitude.len() > out.len() {
            return None;
        }
        let start = out.len() - magnitude.len();
        out[start..].copy_from_slice(magnitude);
        Some(())
    }
}

struct LaxCursor<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> LaxCursor<'a> {
    fn next_byte(&mut self) -> Option<u8> {
        let byte = *self.input.get(self.pos)?;
        self.pos += 1;
        Some(byte)
    }

    fn remaining(&self) -> usize {
        self.input.len() - self.pos
    }

    fn expect_byte(&mut self, expected: u8) -> Option<()> {
        (self.next_byte()? == expected).then_some(())
    }

    fn skip_sequence_length(&mut self) -> Option<()> {
        let lenbyte = self.next_byte()?;
        if lenbyte & 0x80 != 0 {
            let extra = usize::from(lenbyte - 0x80);
            if extra > self.remaining() {
                return None;
            }
            self.pos += extra;
        }
        Some(())
    }

    fn integer(&mut self) -> Option<&'a [u8]> {
        self.expect_byte(0x02)?;
        let len = self.integer_length()?;
        if len > self.remaining() {
            return None;
        }
        let value = &self.input[self.pos..self.pos + len];
        self.pos += len;
        Some(value)
    }

    fn integer_length(&mut self) -> Option<usize> {
        let lenbyte = self.next_byte()?;
        if lenbyte & 0x80 == 0 {
            return Some(usize::from(lenbyte));
        }
        let mut count = usize::from(lenbyte - 0x80);
        if count > self.remaining() {
            return None;
        }
        while count > 0 && self.input[self.pos] == 0 {
            self.pos += 1;
            count -= 1;
        }
        if count >= 4 {
            return None;
        }
        let mut len = 0usize;
        while count > 0 {
            len = (len << 8) + usize::from(self.input[self.pos]);
            self.pos += 1;
            count -= 1;
        }
        Some(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_der_parses_to_the_same_scalars() {
        let sig = [0x30, 0x07, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x05];
        let compact = LaxDer::parse(&sig).expect("parses");
        assert_eq!(compact[31], 0x80);
        assert_eq!(compact[63], 0x05);
        assert!(compact[..31].iter().all(|&b| b == 0));
    }

    #[test]
    fn redundant_leading_zeros_are_stripped() {
        let mut sig = vec![0x30, 0x48, 0x02, 0x22, 0x00, 0x00];
        sig.extend_from_slice(&[0x11; 32]);
        sig.extend_from_slice(&[0x02, 0x22, 0x00, 0x00]);
        sig.extend_from_slice(&[0x22; 32]);
        let compact = LaxDer::parse(&sig).expect("parses");
        assert_eq!(&compact[..32], &[0x11; 32]);
        assert_eq!(&compact[32..], &[0x22; 32]);
    }

    #[test]
    fn wrong_sequence_length_and_trailing_bytes_are_ignored() {
        let sig = [0x30, 0x7f, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0xaa, 0xbb];
        let compact = LaxDer::parse(&sig).expect("parses");
        assert_eq!(compact[31], 0x01);
        assert_eq!(compact[63], 0x02);
    }

    #[test]
    fn long_form_lengths_are_accepted() {
        let sig = [
            0x30, 0x81, 0x08, 0x02, 0x81, 0x01, 0x07, 0x02, 0x82, 0x00, 0x01, 0x09,
        ];
        let compact = LaxDer::parse(&sig).expect("parses");
        assert_eq!(compact[31], 0x07);
        assert_eq!(compact[63], 0x09);
    }

    #[test]
    fn a_magnitude_over_32_bytes_cannot_verify() {
        let mut sig = vec![0x30, 0x45, 0x02, 0x21, 0x01];
        sig.extend_from_slice(&[0x11; 32]);
        sig.extend_from_slice(&[0x02, 0x01, 0x01]);
        assert!(LaxDer::parse(&sig).is_none());
    }

    #[test]
    fn missing_tags_and_truncation_fail() {
        assert!(LaxDer::parse(&[]).is_none());
        assert!(LaxDer::parse(&[0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]).is_none());
        assert!(LaxDer::parse(&[0x30, 0x06, 0x03, 0x01, 0x01, 0x02, 0x01, 0x01]).is_none());
        assert!(LaxDer::parse(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x02, 0x01]).is_none());
        assert!(LaxDer::parse(&[0x30, 0x06, 0x02, 0x84, 0x00, 0x00, 0x00, 0x01]).is_none());
    }
}
