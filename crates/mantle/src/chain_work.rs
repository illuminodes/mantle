use std::fmt;
use std::ops::{Add, AddAssign};

use crate::block::BlockHeader;
use crate::difficulty::CompactBits;

/// The expected number of hashes behind a header or a run of headers,
/// `2^256 / (target + 1)` per header as Bitcoin Core counts it.
///
/// Held in a `u128`: the whole mainnet chain is near `2^96`. A target so
/// hard that one header's work passes `u128::MAX` saturates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ChainWork(u128);

impl ChainWork {
    pub const ZERO: Self = Self(0);

    #[must_use]
    pub const fn new(work: u128) -> Self {
        Self(work)
    }

    #[must_use]
    pub const fn to_u128(self) -> u128 {
        self.0
    }

    /// The work of one header with target `bits`; zero for bits that do not
    /// encode a positive target.
    #[must_use]
    pub fn of_bits(bits: CompactBits) -> Self {
        if bits.to_target().is_none() {
            return Self::ZERO;
        }
        let raw = bits.to_u32();
        let exponent = raw >> 24;
        let mantissa = u128::from(raw & 0x007f_ffff);
        let Some(shift) = exponent.checked_sub(3).map(|bytes| 8 * bytes).filter(|shift| *shift > 128) else {
            return Self(u128::MAX);
        };
        let numerator = 1_u128 << (256 - shift);
        let quotient = numerator / mantissa;
        if numerator.is_multiple_of(mantissa) {
            Self(quotient - 1)
        } else {
            Self(quotient)
        }
    }

    #[must_use]
    pub fn of_header(header: &BlockHeader) -> Self {
        Self::of_bits(header.bits())
    }

    #[must_use]
    pub fn of_headers<'a>(headers: impl IntoIterator<Item = &'a BlockHeader>) -> Self {
        headers.into_iter().map(Self::of_header).fold(Self::ZERO, Add::add)
    }
}

impl Add for ChainWork {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self(self.0.saturating_add(rhs.0))
    }
}

impl AddAssign for ChainWork {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl fmt::Display for ChainWork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::ChainWork;
    use crate::difficulty::CompactBits;

    #[test]
    fn difficulty_one_is_just_over_two_to_the_thirty_two() {
        assert_eq!(ChainWork::of_bits(CompactBits::new(0x1d00_ffff)).to_u128(), 0x1_0001_0001);
    }

    #[test]
    fn the_regtest_target_is_worth_two_hashes() {
        assert_eq!(ChainWork::of_bits(CompactBits::new(0x207f_ffff)).to_u128(), 2);
    }

    #[test]
    fn a_power_of_two_mantissa_divides_exactly_and_loses_one() {
        assert_eq!(ChainWork::of_bits(CompactBits::new(0x2000_8000)).to_u128(), 511);
    }

    #[test]
    fn targets_too_hard_for_the_width_saturate() {
        assert_eq!(ChainWork::of_bits(CompactBits::new(0x1300_ffff)).to_u128(), u128::MAX);
    }

    #[test]
    fn a_harder_target_is_worth_more() {
        let easy = ChainWork::of_bits(CompactBits::new(0x1d00_ffff));
        let hard = ChainWork::of_bits(CompactBits::new(0x1c00_ffff));

        assert!(hard > easy);
    }

    #[test]
    fn bits_without_a_target_are_worth_nothing() {
        assert_eq!(ChainWork::of_bits(CompactBits::new(0x1d00_0000)), ChainWork::ZERO);
        assert_eq!(ChainWork::of_bits(CompactBits::new(0x0180_0001)), ChainWork::ZERO);
    }

    #[test]
    fn sums_saturate() {
        assert_eq!(ChainWork::new(u128::MAX) + ChainWork::new(1), ChainWork::new(u128::MAX));
    }
}
