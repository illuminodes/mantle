#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct WnafDigits {
    digits: [i8; Self::LEN],
    top: usize,
}

impl WnafDigits {
    pub(super) const LEN: usize = 129;

    #[expect(clippy::cast_possible_truncation, reason = "window value is below 2^8")]
    pub(super) fn new(value: u128, negative: bool, window: u32) -> Self {
        let width = 1i16 << window;
        let mask = (1u128 << window) - 1;
        let mut digits = [0i8; Self::LEN];
        let mut top = 0;
        let mut carry = 0i16;
        let mut pos = 0usize;
        while pos < Self::LEN {
            let bits = value.checked_shr(pos as u32).unwrap_or(0) & mask;
            let window_val = carry + bits as i16;
            if window_val & 1 == 0 {
                pos += 1;
                continue;
            }
            let digit = if window_val < width / 2 {
                carry = 0;
                window_val
            } else {
                carry = 1;
                window_val - width
            };
            digits[pos] = if negative { -digit } else { digit } as i8;
            top = pos + 1;
            pos += window as usize;
        }
        Self { digits, top }
    }

    pub(super) fn top(&self) -> usize {
        self.top
    }

    pub(super) fn at(&self, pos: usize) -> i8 {
        self.digits[pos]
    }
}

#[cfg(test)]
mod tests {
    use super::WnafDigits;

    impl WnafDigits {
        fn evaluate(&self) -> i128 {
            assert!(self.top < 127, "evaluate only fits values below 2^126");
            self.digits[..self.top]
                .iter()
                .enumerate()
                .map(|(pos, &d)| i128::from(d) << pos)
                .sum()
        }

        fn samples() -> impl Iterator<Item = u128> {
            [0, 1, 2, 3, 15, 16, 17, 255, (1 << 120) - 1, 1 << 120]
                .into_iter()
                .chain((0u64..5_000).map(|i| {
                    u128::from(i).wrapping_mul(0x9e37_79b9_7f4a_7c15_f39c_c060_5ced_c835) >> 8
                }))
        }
    }

    #[test]
    fn digits_sum_to_the_value_with_sign() {
        for window in [2, 5, 8] {
            for v in WnafDigits::samples() {
                let v_i = i128::try_from(v).expect("sample below 2^120");
                assert_eq!(WnafDigits::new(v, false, window).evaluate(), v_i);
                assert_eq!(WnafDigits::new(v, true, window).evaluate(), -v_i);
            }
        }
    }

    #[test]
    fn digits_are_odd_bounded_and_spaced() {
        for window in [5, 8] {
            let bound = 1i16 << (window - 1);
            for v in WnafDigits::samples() {
                let w = WnafDigits::new(v, false, window);
                let mut last: Option<usize> = None;
                for pos in 0..WnafDigits::LEN {
                    let d = i16::from(w.at(pos));
                    if d == 0 {
                        continue;
                    }
                    assert_eq!(d & 1, 1, "digit {d} must be odd");
                    assert!(d.abs() < bound);
                    if let Some(prev) = last {
                        assert!(pos - prev >= window as usize);
                    }
                    last = Some(pos);
                }
                assert_eq!(w.top(), last.map_or(0, |p| p + 1));
            }
        }
    }

    #[test]
    fn full_width_value_carries_into_the_last_digit() {
        let w = WnafDigits::new(u128::MAX, false, 5);
        assert_eq!(w.at(128), 1);
        assert_eq!(w.top(), 129);
    }
}
