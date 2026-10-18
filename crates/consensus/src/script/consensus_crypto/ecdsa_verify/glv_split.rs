use std::sync::LazyLock;

use k256::elliptic_curve::ff::PrimeField;
use k256::elliptic_curve::scalar::IsHigh;
use k256::{FieldBytes, Scalar};

#[expect(
    clippy::struct_field_names,
    reason = "each field holds the negated constant"
)]
struct GlvLattice {
    neg_lambda: Scalar,
    neg_b1: Scalar,
    neg_b2: Scalar,
}

static LATTICE: LazyLock<GlvLattice> = LazyLock::new(GlvLattice::new);

impl GlvLattice {
    const G1: [u64; 4] = [
        0xe893_209a_45db_b031,
        0x3daa_8a14_71e8_ca7f,
        0xe86c_90e4_9284_eb15,
        0x3086_d221_a7d4_6bcd,
    ];
    const G2: [u64; 4] = [
        0x1571_b4ae_8ac4_7f71,
        0x2212_08ac_9df5_06c6,
        0x6f54_7fa9_0abf_e4c4,
        0xe443_7ed6_010e_8828,
    ];

    fn new() -> Self {
        Self {
            neg_lambda: Self::scalar([
                0xac, 0x9c, 0x52, 0xb3, 0x3f, 0xa3, 0xcf, 0x1f, 0x5a, 0xd9, 0xe3, 0xfd, 0x77, 0xed,
                0x9b, 0xa4, 0xa8, 0x80, 0xb9, 0xfc, 0x8e, 0xc7, 0x39, 0xc2, 0xe0, 0xcf, 0xc8, 0x10,
                0xb5, 0x12, 0x83, 0xcf,
            ]),
            neg_b1: Self::scalar([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xe4, 0x43, 0x7e, 0xd6, 0x01, 0x0e,
                0x88, 0x28, 0x6f, 0x54, 0x7f, 0xa9, 0x0a, 0xbf, 0xe4, 0xc3,
            ]),
            neg_b2: Self::scalar([
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xfe, 0x8a, 0x28, 0x0a, 0xc5, 0x07, 0x74, 0x34, 0x6d, 0xd7, 0x65, 0xcd, 0xa8,
                0x3d, 0xb1, 0x56, 0x2c,
            ]),
        }
    }

    fn scalar(be: [u8; 32]) -> Scalar {
        Scalar::from_repr(FieldBytes::from(be)).expect("lattice constant below the group order")
    }

    fn limbs(k: &Scalar) -> [u64; 4] {
        let be = k.to_bytes();
        core::array::from_fn(|i| {
            let start = 24 - 8 * i;
            u64::from_be_bytes(be[start..start + 8].try_into().expect("8-byte limb"))
        })
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "low limb of a 128-bit product"
    )]
    fn rounded_shift_384(k: &[u64; 4], g: &[u64; 4]) -> u128 {
        let mut wide = [0u64; 8];
        for (i, &ki) in k.iter().enumerate() {
            let mut carry = 0u128;
            for (j, &gj) in g.iter().enumerate() {
                let t = u128::from(ki) * u128::from(gj) + u128::from(wide[i + j]) + carry;
                wide[i + j] = t as u64;
                carry = t >> 64;
            }
            wide[i + 4] = carry as u64;
        }
        let quotient = u128::from(wide[6]) | (u128::from(wide[7]) << 64);
        quotient + u128::from(wide[5] >> 63)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct GlvSplit {
    pub(super) halves: [u128; 2],
    pub(super) negative: [bool; 2],
}

impl GlvSplit {
    pub(super) fn of(k: &Scalar) -> Option<Self> {
        let lattice = &*LATTICE;
        let limbs = GlvLattice::limbs(k);
        let c1 = Scalar::from(GlvLattice::rounded_shift_384(&limbs, &GlvLattice::G1));
        let c2 = Scalar::from(GlvLattice::rounded_shift_384(&limbs, &GlvLattice::G2));
        let r2 = c1 * lattice.neg_b1 + c2 * lattice.neg_b2;
        let r1 = *k + r2 * lattice.neg_lambda;
        let (h1, n1) = Self::signed_half(&r1)?;
        let (h2, n2) = Self::signed_half(&r2)?;
        Some(Self {
            halves: [h1, h2],
            negative: [n1, n2],
        })
    }

    fn signed_half(r: &Scalar) -> Option<(u128, bool)> {
        let negative = bool::from(r.is_high());
        let magnitude = if negative { -*r } else { *r };
        let be = magnitude.to_bytes();
        let (high, low) = be.split_at(16);
        if high.iter().any(|&b| b != 0) {
            return None;
        }
        let half = u128::from_be_bytes(low.try_into().expect("16-byte half"));
        Some((half, negative))
    }
}

#[cfg(test)]
mod tests {
    use super::{GlvLattice, GlvSplit, LATTICE};
    use k256::Scalar;
    use k256::elliptic_curve::ops::Reduce;
    use sha2::{Digest, Sha256};

    impl GlvSplit {
        fn recombined(&self) -> Scalar {
            let [r1, r2] = self.signed();
            r1 - r2 * LATTICE.neg_lambda
        }

        fn signed(&self) -> [Scalar; 2] {
            core::array::from_fn(|i| {
                let s = Scalar::from(self.halves[i]);
                if self.negative[i] { -s } else { s }
            })
        }

        fn sampled_scalars() -> impl Iterator<Item = Scalar> {
            let edges = [
                Scalar::ZERO,
                Scalar::ONE,
                -Scalar::ONE,
                -LATTICE.neg_lambda,
                LATTICE.neg_lambda,
            ];
            let hashed = (0u32..20_000).map(|i| {
                let digest: [u8; 32] = Sha256::digest(i.to_le_bytes()).into();
                <Scalar as Reduce<k256::FieldBytes>>::reduce(&digest.into())
            });
            edges.into_iter().chain(hashed)
        }
    }

    #[test]
    fn halves_recombine_to_the_scalar() {
        for k in GlvSplit::sampled_scalars() {
            let split = GlvSplit::of(&k).expect("halves fit in 128 bits");
            assert_eq!(split.recombined(), k);
        }
    }

    #[test]
    fn rounded_shift_rounds_half_up() {
        let two_pow_255 = [0, 0, 0, 1 << 63];
        let two_pow_128 = [0, 0, 1, 0];
        let below_half = [0, 0, 0, 1 << 62];
        assert_eq!(GlvLattice::rounded_shift_384(&two_pow_255, &two_pow_128), 1);
        assert_eq!(GlvLattice::rounded_shift_384(&below_half, &two_pow_128), 0);
    }
}
