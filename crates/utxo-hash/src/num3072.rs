/// An integer modulo `p = 2^3072 - 1103717`, the `MuHash3072` group modulus.
///
/// Stored as 48 little-endian 64-bit limbs, the byte layout of Core's
/// `Num3072`. Arithmetic results are always fully reduced; values parsed from
/// bytes may be any 3072-bit integer and are reduced by the first operation.
#[derive(Clone, PartialEq, Eq)]
pub struct Num3072 {
    limbs: [u64; Self::LIMBS],
}

impl Num3072 {
    pub const BYTE_SIZE: usize = 384;
    const LIMBS: usize = 48;
    const PRIME_DIFF: u64 = 1_103_717;

    #[must_use]
    pub fn one() -> Self {
        let mut limbs = [0u64; Self::LIMBS];
        limbs[0] = 1;
        Self { limbs }
    }

    #[must_use]
    pub fn from_bytes(bytes: &[u8; Self::BYTE_SIZE]) -> Self {
        let mut limbs = [0u64; Self::LIMBS];
        for (limb, chunk) in limbs.iter_mut().zip(bytes.chunks_exact(8)) {
            let mut le = [0u8; 8];
            le.copy_from_slice(chunk);
            *limb = u64::from_le_bytes(le);
        }
        Self { limbs }
    }

    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::BYTE_SIZE] {
        let mut out = [0u8; Self::BYTE_SIZE];
        for (chunk, limb) in out.chunks_exact_mut(8).zip(self.limbs) {
            chunk.copy_from_slice(&limb.to_le_bytes());
        }
        out
    }

    /// `self * other mod p`.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn mul(&self, other: &Self) -> Self {
        let mut wide = [0u64; 2 * Self::LIMBS];
        for (i, &a) in self.limbs.iter().enumerate() {
            let mut carry: u128 = 0;
            for (j, &b) in other.limbs.iter().enumerate() {
                let t = u128::from(a) * u128::from(b) + u128::from(wide[i + j]) + carry;
                wide[i + j] = t as u64;
                carry = t >> 64;
            }
            wide[i + Self::LIMBS] = carry as u64;
        }
        Self::reduce_wide(&wide)
    }

    /// `self^-1 mod p` by Fermat's little theorem; `p` is prime.
    #[must_use]
    pub fn inverse(&self) -> Self {
        let mut exponent = [u64::MAX; Self::LIMBS];
        exponent[0] = 0u64.wrapping_sub(Self::PRIME_DIFF + 2);
        let mut result = Self::one();
        for limb in exponent.iter().rev() {
            for bit in (0..64).rev() {
                result = result.mul(&result);
                if (limb >> bit) & 1 == 1 {
                    result = result.mul(self);
                }
            }
        }
        result
    }

    #[allow(clippy::cast_possible_truncation)]
    fn reduce_wide(wide: &[u64; 2 * Self::LIMBS]) -> Self {
        let mut low = [0u64; Self::LIMBS];
        low.copy_from_slice(&wide[..Self::LIMBS]);
        let mut carry: u128 = 0;
        for (limb, &high) in low.iter_mut().zip(&wide[Self::LIMBS..]) {
            let t = u128::from(*limb) + u128::from(high) * u128::from(Self::PRIME_DIFF) + carry;
            *limb = t as u64;
            carry = t >> 64;
        }
        let mut value = Self { limbs: low };
        value.fold(carry as u64);
        value
    }

    /// Reduce `self + overflow * 2^3072` to a value below `p`.
    #[allow(clippy::cast_possible_truncation)]
    fn fold(&mut self, mut overflow: u64) {
        while overflow != 0 {
            let mut carry = u128::from(overflow) * u128::from(Self::PRIME_DIFF);
            for limb in &mut self.limbs {
                if carry == 0 {
                    break;
                }
                let t = u128::from(*limb) + carry;
                *limb = t as u64;
                carry = t >> 64;
            }
            overflow = carry as u64;
        }
        if self.is_at_least_modulus() {
            self.subtract_modulus();
        }
    }

    fn is_at_least_modulus(&self) -> bool {
        self.limbs[0] > u64::MAX - Self::PRIME_DIFF && self.limbs[1..].iter().all(|&l| l == u64::MAX)
    }

    fn subtract_modulus(&mut self) {
        self.limbs[0] = self.limbs[0].wrapping_add(Self::PRIME_DIFF);
        self.limbs[1..].fill(0);
    }
}

impl std::fmt::Debug for Num3072 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Num3072(0x")?;
        for limb in self.limbs.iter().rev() {
            write!(f, "{limb:016x}")?;
        }
        write!(f, ")")
    }
}

#[cfg(test)]
mod tests {
    use super::Num3072;

    fn small(n: u64) -> Num3072 {
        let mut value = Num3072::one();
        value.limbs[0] = n;
        value
    }

    fn modulus_minus(k: u64) -> Num3072 {
        let mut limbs = [u64::MAX; Num3072::LIMBS];
        limbs[0] = 0u64.wrapping_sub(Num3072::PRIME_DIFF + k);
        Num3072 { limbs }
    }

    #[test]
    fn small_products_are_exact() {
        assert_eq!(small(6).mul(&small(7)), small(42));
    }

    #[test]
    fn minus_one_squared_is_one() {
        let minus_one = modulus_minus(1);
        assert_eq!(minus_one.mul(&minus_one), Num3072::one());
    }

    #[test]
    fn minus_one_times_two_is_minus_two() {
        assert_eq!(modulus_minus(1).mul(&small(2)), modulus_minus(2));
    }

    #[test]
    fn values_at_or_above_the_modulus_reduce() {
        let p = modulus_minus(0);
        assert_eq!(p.mul(&Num3072::one()), small(0));
        let p_plus_5 = {
            let mut v = modulus_minus(0);
            v.limbs[0] = v.limbs[0].wrapping_add(5);
            v
        };
        assert_eq!(p_plus_5.mul(&Num3072::one()), small(5));
        let all_ones = Num3072 {
            limbs: [u64::MAX; Num3072::LIMBS],
        };
        assert_eq!(all_ones.mul(&Num3072::one()), small(Num3072::PRIME_DIFF - 1));
    }

    #[test]
    fn inverse_times_value_is_one() {
        for value in [small(2), small(1_103_717), modulus_minus(1), modulus_minus(12_345)] {
            assert_eq!(value.mul(&value.inverse()), Num3072::one(), "{value:?}");
        }
    }

    #[test]
    fn bytes_round_trip() {
        let value = modulus_minus(77);
        assert_eq!(Num3072::from_bytes(&value.to_bytes()), value);
    }
}
