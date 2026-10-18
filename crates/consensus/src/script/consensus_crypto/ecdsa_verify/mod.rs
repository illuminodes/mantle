mod generator_tables;
mod glv_split;
mod odd_multiples;
mod wnaf_digits;

use k256::elliptic_curve::Group;
use k256::elliptic_curve::ops::{MulByGeneratorVartime, Reduce};
use k256::elliptic_curve::point::AffineCoordinates;
use k256::{FieldBytes, ProjectivePoint, Scalar};

use generator_tables::GeneratorTables;
use glv_split::GlvSplit;
use odd_multiples::OddMultiples;
use wnaf_digits::WnafDigits;

pub struct EcdsaVerifier;

impl EcdsaVerifier {
    const KEY_WINDOW: u32 = 5;

    #[must_use]
    pub fn verify(key: &ProjectivePoint, digest: &[u8; 32], r: &Scalar, s: &Scalar) -> bool {
        if bool::from(r.is_zero()) || bool::from(s.is_zero()) {
            return false;
        }
        let Some(s_inv) = Option::<Scalar>::from(s.invert_vartime()) else {
            return false;
        };
        let message = <Scalar as Reduce<FieldBytes>>::reduce(&FieldBytes::from(*digest));
        let point = Self::double_scalar_mul(&(message * s_inv), &(*r * s_inv), key);
        if bool::from(point.is_identity()) {
            return false;
        }
        let point_x = <Scalar as Reduce<FieldBytes>>::reduce(&point.to_affine().x());
        point_x == *r
    }

    #[must_use]
    pub fn double_scalar_mul(u1: &Scalar, u2: &Scalar, q: &ProjectivePoint) -> ProjectivePoint {
        match (GlvSplit::of(u1), GlvSplit::of(u2)) {
            (Some(g_split), Some(q_split)) => Self::straus(&g_split, &q_split, q),
            _ => ProjectivePoint::mul_by_generator_and_mul_add_vartime(u1, u2, q),
        }
    }

    fn straus(g_split: &GlvSplit, q_split: &GlvSplit, q: &ProjectivePoint) -> ProjectivePoint {
        let generator = GeneratorTables::shared();
        let q_table = OddMultiples::<8>::of(q);
        let q_lambda_table = q_table.endomorphism();
        let digits = [
            WnafDigits::new(
                g_split.halves[0],
                g_split.negative[0],
                GeneratorTables::WINDOW,
            ),
            WnafDigits::new(
                g_split.halves[1],
                g_split.negative[1],
                GeneratorTables::WINDOW,
            ),
            WnafDigits::new(q_split.halves[0], q_split.negative[0], Self::KEY_WINDOW),
            WnafDigits::new(q_split.halves[1], q_split.negative[1], Self::KEY_WINDOW),
        ];
        let top = digits.iter().map(WnafDigits::top).max().unwrap_or(0);
        let mut acc = ProjectivePoint::IDENTITY;
        for pos in (0..top).rev() {
            acc = acc.double();
            generator.base.add_digit(&mut acc, digits[0].at(pos));
            generator.lambda.add_digit(&mut acc, digits[1].at(pos));
            q_table.add_digit(&mut acc, digits[2].at(pos));
            q_lambda_table.add_digit(&mut acc, digits[3].at(pos));
        }
        acc
    }
}

#[cfg(test)]
mod tests;
