use mantle::primitives::Hash256;
use sha2::{Digest, Sha256};

use crate::chacha20::ChaCha20Keystream;
use crate::num3072::Num3072;

/// Bitcoin Core's `MuHash3072`: a hash of a multiset that supports adding and
/// removing elements in any order.
#[derive(Clone, Debug)]
pub struct MuHash3072 {
    numerator: Num3072,
    denominator: Num3072,
}

impl MuHash3072 {
    #[must_use]
    pub fn new() -> Self {
        Self {
            numerator: Num3072::one(),
            denominator: Num3072::one(),
        }
    }

    pub fn insert(&mut self, element: &[u8]) {
        self.numerator = self.numerator.mul(&Self::element(element));
    }

    pub fn remove(&mut self, element: &[u8]) {
        self.denominator = self.denominator.mul(&Self::element(element));
    }

    /// Add every element of `other` to `self`.
    pub fn combine(&mut self, other: &Self) {
        self.numerator = self.numerator.mul(&other.numerator);
        self.denominator = self.denominator.mul(&other.denominator);
    }

    /// Remove every element of `other` from `self`.
    pub fn subtract(&mut self, other: &Self) {
        self.numerator = self.numerator.mul(&other.denominator);
        self.denominator = self.denominator.mul(&other.numerator);
    }

    /// The 32-byte digest, as Core's `MuHash3072::Finalize` produces it.
    #[must_use]
    pub fn finalize(&self) -> Hash256 {
        let value = self.numerator.mul(&self.denominator.inverse());
        Hash256::from_bytes(Sha256::digest(value.to_bytes()).into())
    }

    /// Numerator then denominator, each as 384 little-endian bytes.
    #[must_use]
    pub fn to_state_bytes(&self) -> [u8; 2 * Num3072::BYTE_SIZE] {
        let mut out = [0u8; 2 * Num3072::BYTE_SIZE];
        out[..Num3072::BYTE_SIZE].copy_from_slice(&self.numerator.to_bytes());
        out[Num3072::BYTE_SIZE..].copy_from_slice(&self.denominator.to_bytes());
        out
    }

    #[must_use]
    pub fn from_state_bytes(bytes: &[u8; 2 * Num3072::BYTE_SIZE]) -> Self {
        let mut numerator = [0u8; Num3072::BYTE_SIZE];
        let mut denominator = [0u8; Num3072::BYTE_SIZE];
        numerator.copy_from_slice(&bytes[..Num3072::BYTE_SIZE]);
        denominator.copy_from_slice(&bytes[Num3072::BYTE_SIZE..]);
        Self {
            numerator: Num3072::from_bytes(&numerator),
            denominator: Num3072::from_bytes(&denominator),
        }
    }

    fn element(data: &[u8]) -> Num3072 {
        let key: [u8; 32] = Sha256::digest(data).into();
        let mut bytes = [0u8; Num3072::BYTE_SIZE];
        ChaCha20Keystream::new(&key).fill(&mut bytes);
        Num3072::from_bytes(&bytes)
    }

    #[cfg(test)]
    fn from_parts(numerator: Num3072, denominator: Num3072) -> Self {
        Self {
            numerator,
            denominator,
        }
    }

    #[cfg(test)]
    fn numerator_bytes(&self) -> [u8; Num3072::BYTE_SIZE] {
        self.numerator.to_bytes()
    }
}

impl Default for MuHash3072 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{MuHash3072, Num3072};
    use crate::test_hex::TestHex;

    struct CoreVector;

    impl CoreVector {
        fn from_int(i: u8) -> MuHash3072 {
            let mut set = MuHash3072::new();
            set.insert(&Self::int_bytes(i));
            set
        }

        fn int_bytes(i: u8) -> [u8; 32] {
            let mut bytes = [0u8; 32];
            bytes[0] = i;
            bytes
        }
    }

    #[test]
    fn core_vector_combine_and_subtract() {
        let mut acc = CoreVector::from_int(0);
        acc.combine(&CoreVector::from_int(1));
        acc.subtract(&CoreVector::from_int(2));
        assert_eq!(
            acc.finalize().to_display_hex(),
            "10d312b100cbd32ada024a6646e40d3482fcff103668d2625f10002a607d5863"
        );
    }

    #[test]
    fn core_vector_insert_and_remove() {
        let mut acc = CoreVector::from_int(0);
        acc.insert(&CoreVector::int_bytes(1));
        acc.remove(&CoreVector::int_bytes(2));
        assert_eq!(
            acc.finalize().to_display_hex(),
            "10d312b100cbd32ada024a6646e40d3482fcff103668d2625f10002a607d5863"
        );
    }

    #[test]
    fn core_vector_serialized_numerator() {
        let mut set = CoreVector::from_int(1);
        set.combine(&CoreVector::from_int(2));
        let expected = "1fa093295ea30a6a3acdc7b3f770fa538eff537528e990e2910e40bbcfd7f6696b1256901929094694b56316de342f593303dd12ac43e06dce1be1ff8301c845beb15468fff0ef002dbf80c29f26e6452bccc91b5cb9437ad410d2a67ea847887fa3c6a6553309946880fe20db2c73fe0641adbd4e86edfee0d9f8cd0ee1230898873dc13ed8ddcaf045c80faa082774279007a2253f8922ee3ef361d378a6af3ddaf180b190ac97e556888c36b3d1fb1c85aab9ccd46e3deaeb7b7cf5db067a7e9ff86b658cf3acd6662bbcce37232daa753c48b794356c020090c831a8304416e2aa7ad633c0ddb2f11be1be316a81be7f7e472071c042cb68faef549c221ebff209273638b741aba5a81675c45a5fa92fea4ca821d7a324cb1e1a2ccd3b76c4228ec8066dad2a5df6e1bd0de45c7dd5de8070bdb46db6c554cf9aefc9b7b2bbf9f75b1864d9f95005314593905c0109b71f703d49944ae94477b51dac10a816bb6d1c700bafabc8bd86fac8df24be519a2f2836b16392e18036cb13e48c5c";
        assert_eq!(TestHex::encode(&set.numerator_bytes()), expected);
    }

    #[test]
    fn core_vector_overflowing_numerator() {
        let set = MuHash3072::from_parts(
            Num3072::from_bytes(&[0xff; Num3072::BYTE_SIZE]),
            Num3072::one(),
        );
        assert_eq!(
            TestHex::encode(set.finalize().as_bytes()),
            "3a31e6903aff0de9f62f9a9f7f8b861de76ce2cda09822b90014319ae5dc2271"
        );
    }

    #[test]
    fn order_of_operations_does_not_matter() {
        let elements: [&[u8]; 4] = [b"a", b"bb", b"ccc", b"dddd"];
        let mut forward = MuHash3072::new();
        for e in elements {
            forward.insert(e);
        }
        forward.remove(b"bb");
        let mut backward = MuHash3072::new();
        backward.remove(b"bb");
        for e in elements.iter().rev() {
            backward.insert(e);
        }
        assert_eq!(forward.finalize(), backward.finalize());
    }

    #[test]
    fn removing_everything_gives_the_empty_set() {
        let mut set = MuHash3072::new();
        set.insert(b"x");
        set.insert(b"y");
        set.remove(b"y");
        set.remove(b"x");
        assert_eq!(set.finalize(), MuHash3072::new().finalize());
    }
}
