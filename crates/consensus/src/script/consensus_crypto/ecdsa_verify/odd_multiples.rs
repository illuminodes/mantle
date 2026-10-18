use k256::ProjectivePoint;

pub(super) struct OddMultiples<const N: usize> {
    points: [ProjectivePoint; N],
}

impl<const N: usize> OddMultiples<N> {
    pub(super) fn of(base: &ProjectivePoint) -> Self {
        let twice = base.double();
        let mut next = *base;
        Self {
            points: core::array::from_fn(|_| {
                let entry = next;
                next += twice;
                entry
            }),
        }
    }

    pub(super) fn endomorphism(&self) -> Self {
        Self {
            points: self.points.map(|p| p.endomorphism()),
        }
    }

    pub(super) fn add_digit(&self, acc: &mut ProjectivePoint, digit: i8) {
        let index = usize::from(digit.unsigned_abs() >> 1);
        if digit > 0 {
            *acc += self.points[index];
        } else if digit < 0 {
            *acc -= self.points[index];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::OddMultiples;
    use k256::{ProjectivePoint, Scalar};

    #[test]
    fn entries_are_consecutive_odd_multiples() {
        let g = ProjectivePoint::GENERATOR;
        let table = OddMultiples::<8>::of(&g);
        for (i, p) in table.points.iter().enumerate() {
            let k = u64::try_from(2 * i + 1).expect("small index");
            assert_eq!(*p, g * Scalar::from(k));
        }
    }

    #[test]
    fn add_digit_applies_sign_and_skips_zero() {
        let g = ProjectivePoint::GENERATOR;
        let table = OddMultiples::<8>::of(&g);
        for digit in (-15i8..=15).filter(|d| d % 2 != 0 || *d == 0) {
            let mut acc = g;
            table.add_digit(&mut acc, digit);
            let expected = if digit == 0 {
                g
            } else {
                let k = g * Scalar::from(u64::from(digit.unsigned_abs()));
                if digit > 0 { g + k } else { g - k }
            };
            assert_eq!(acc, expected, "digit {digit}");
        }
    }

    #[test]
    fn endomorphism_table_matches_table_of_endomorphism() {
        let g = ProjectivePoint::GENERATOR;
        let mapped = OddMultiples::<8>::of(&g).endomorphism();
        let direct = OddMultiples::<8>::of(&g.endomorphism());
        assert_eq!(mapped.points, direct.points);
    }
}
