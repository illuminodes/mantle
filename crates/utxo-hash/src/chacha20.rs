/// `ChaCha20` keystream (RFC 8439) with a zero nonce, as Core's
/// `ChaCha20Aligned` produces it for `MuHash` element expansion.
pub struct ChaCha20Keystream {
    state: [u32; 16],
}

impl ChaCha20Keystream {
    const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];
    const BLOCK_LEN: usize = 64;

    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        let mut state = [0u32; 16];
        state[..4].copy_from_slice(&Self::CONSTANTS);
        for (word, chunk) in state[4..12].iter_mut().zip(key.chunks_exact(4)) {
            let mut le = [0u8; 4];
            le.copy_from_slice(chunk);
            *word = u32::from_le_bytes(le);
        }
        Self { state }
    }

    /// Position the keystream at block `counter`.
    pub fn seek(&mut self, counter: u32) {
        self.state[12] = counter;
    }

    pub fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(Self::BLOCK_LEN) {
            let block = self.block();
            chunk.copy_from_slice(&block[..chunk.len()]);
            self.state[12] = self.state[12].wrapping_add(1);
        }
    }

    fn block(&self) -> [u8; Self::BLOCK_LEN] {
        let mut x = self.state;
        for _ in 0..10 {
            Self::quarter_round(&mut x, 0, 4, 8, 12);
            Self::quarter_round(&mut x, 1, 5, 9, 13);
            Self::quarter_round(&mut x, 2, 6, 10, 14);
            Self::quarter_round(&mut x, 3, 7, 11, 15);
            Self::quarter_round(&mut x, 0, 5, 10, 15);
            Self::quarter_round(&mut x, 1, 6, 11, 12);
            Self::quarter_round(&mut x, 2, 7, 8, 13);
            Self::quarter_round(&mut x, 3, 4, 9, 14);
        }
        let mut out = [0u8; Self::BLOCK_LEN];
        for ((chunk, word), initial) in out.chunks_exact_mut(4).zip(x).zip(self.state) {
            chunk.copy_from_slice(&word.wrapping_add(initial).to_le_bytes());
        }
        out
    }

    #[allow(clippy::many_single_char_names)]
    fn quarter_round(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        x[a] = x[a].wrapping_add(x[b]);
        x[d] = (x[d] ^ x[a]).rotate_left(16);
        x[c] = x[c].wrapping_add(x[d]);
        x[b] = (x[b] ^ x[c]).rotate_left(12);
        x[a] = x[a].wrapping_add(x[b]);
        x[d] = (x[d] ^ x[a]).rotate_left(8);
        x[c] = x[c].wrapping_add(x[d]);
        x[b] = (x[b] ^ x[c]).rotate_left(7);
    }
}

#[cfg(test)]
mod tests {
    use super::ChaCha20Keystream;
    use crate::test_hex::TestHex;

    fn keystream(key_hex: &str, counter: u32, len: usize) -> String {
        let key: [u8; 32] = TestHex::decode(key_hex).try_into().expect("32-byte key");
        let mut stream = ChaCha20Keystream::new(&key);
        stream.seek(counter);
        let mut out = vec![0u8; len];
        stream.fill(&mut out);
        TestHex::encode(&out)
    }

    #[test]
    fn rfc8439_a1_vector_1() {
        assert_eq!(
            keystream(&"00".repeat(32), 0, 64),
            "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7\
             da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586"
        );
    }

    #[test]
    fn rfc8439_a1_vector_2() {
        assert_eq!(
            keystream(&"00".repeat(32), 1, 64),
            "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed\
             29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f"
        );
    }

    #[test]
    fn rfc8439_a1_vector_3() {
        let key = format!("{}01", "00".repeat(31));
        assert_eq!(
            keystream(&key, 1, 64),
            "3aeb5224ecf849929b9d828db1ced4dd832025e8018b8160b82284f3c949aa5a\
             8eca00bbb4a73bdad192b5c42f73f2fd4e273644c8b36125a64addeb006c13a0"
        );
    }

    #[test]
    fn fill_continues_across_blocks() {
        let whole = keystream(&"00".repeat(32), 0, 128);
        assert_eq!(&whole[..128], keystream(&"00".repeat(32), 0, 64));
        assert_eq!(&whole[128..], keystream(&"00".repeat(32), 1, 64));
    }
}
