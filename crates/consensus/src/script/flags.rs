//! Script verify flags and per-height activation table.
//!
//! `ScriptFlags` is a `u32` newtype with associated `const` named bits.
//! Bit positions match `bitcoinconsensus`'s public C ABI so the differential
//! fuzzer can pass the same value to both sides without translation.

use std::ops::{BitAnd, BitOr, BitOrAssign, Not, Sub};

use mantle::primitives::BlockHeight;

/// Script verification flags. Bit positions match `bitcoinconsensus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ScriptFlags(u32);

impl ScriptFlags {
    /// No flags. Pre-soft-fork baseline.
    pub const NONE: Self = Self(0);

    /// BIP16 — pay-to-script-hash.
    pub const P2SH: Self = Self(1 << 0);

    /// Strict encoding for signatures and public keys (BIP62 partial).
    pub const STRICTENC: Self = Self(1 << 1);

    /// BIP66 — strict-DER signature encoding.
    pub const DERSIG: Self = Self(1 << 2);

    /// BIP62 — low-S signatures only.
    pub const LOW_S: Self = Self(1 << 3);

    /// BIP147 — `OP_CHECKMULTISIG` dummy element must be the empty push.
    pub const NULLDUMMY: Self = Self(1 << 4);

    /// BIP62 rule 2 — scriptSig must contain only push operations.
    pub const SIGPUSHONLY: Self = Self(1 << 5);

    /// BIP62 rule 3 — pushes must use the minimal opcode.
    pub const MINIMALDATA: Self = Self(1 << 6);

    /// Reserved-NOP usage is discouraged in mempool / standardness.
    pub const DISCOURAGE_UPGRADABLE_NOPS: Self = Self(1 << 7);

    /// BIP62 rule 6 — final stack must be exactly one truthy element.
    pub const CLEANSTACK: Self = Self(1 << 8);

    /// BIP65 — `OP_CHECKLOCKTIMEVERIFY`.
    pub const CHECKLOCKTIMEVERIFY: Self = Self(1 << 9);

    /// BIP112 — `OP_CHECKSEQUENCEVERIFY`.
    pub const CHECKSEQUENCEVERIFY: Self = Self(1 << 10);

    /// BIP141 — segwit witness program execution.
    pub const WITNESS: Self = Self(1 << 11);

    /// Witness program of unknown version is not accepted in mempool.
    pub const DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM: Self = Self(1 << 12);

    /// `OP_IF`/`OP_NOTIF` operand must be exactly 0x00 or 0x01.
    pub const MINIMALIF: Self = Self(1 << 13);

    /// Failed `OP_CHECKSIG`/`OP_CHECKMULTISIG` must produce an empty signature.
    pub const NULLFAIL: Self = Self(1 << 14);

    /// Witness pubkey must be compressed.
    pub const WITNESS_PUBKEYTYPE: Self = Self(1 << 15);

    /// scriptCode signed by `OP_CHECKSIG` must not contain `OP_CODESEPARATOR`.
    pub const CONST_SCRIPTCODE: Self = Self(1 << 16);

    /// BIP341/342 — taproot key-path and tapscript.
    pub const TAPROOT: Self = Self(1 << 17);

    /// Discourage taproot leaf versions other than 0xC0.
    pub const DISCOURAGE_UPGRADABLE_TAPROOT_VERSION: Self = Self(1 << 18);

    /// Discourage `OP_SUCCESSx` opcodes (forward-compat soft-fork lever).
    pub const DISCOURAGE_OP_SUCCESS: Self = Self(1 << 19);

    /// Discourage non-default pubkey types in taproot.
    pub const DISCOURAGE_UPGRADABLE_PUBKEYTYPE: Self = Self(1 << 20);

    /// Mainnet activation heights, in chronological order. Each entry adds
    /// flag bits at the named height; flags are cumulative.
    ///
    /// Core instead enables P2SH, WITNESS and TAPROOT from genesis and exempts
    /// two blocks (`…9c22` at 170,060 and `…95ad` at 692,261). Both lie below
    /// the activation heights here, so the two schemes agree on the mainnet
    /// chain; `tests_script_flag_history` checks the two exempt spends.
    const ACTIVATIONS: &'static [(u32, Self)] = &[
        (173_805, Self::P2SH),                           // BIP16
        (363_725, Self::DERSIG),                         // BIP66
        (388_381, Self::CHECKLOCKTIMEVERIFY),            // BIP65
        (419_328, Self::CHECKSEQUENCEVERIFY),            // BIP112/68/113
        (481_824, Self::WITNESS.union(Self::NULLDUMMY)), // BIP141/143/147
        (709_633, Self::TAPROOT),                        // BIP341/342
    ];

    /// Construct from raw bits — for fuzzer parity. Prefer the named constants.
    #[inline]
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Raw bit representation, matching `bitcoinconsensus`'s `u32`.
    #[inline]
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// `true` if every bit in `other` is set in `self`.
    #[inline]
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Bitwise union — `const`-friendly companion to `BitOr`.
    #[inline]
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Mainnet flag set active at `height`, matching Core's behaviour.
    ///
    /// The conformance tests compare this against `bitcoinconsensus::height_to_flags`.
    #[must_use]
    pub fn for_height(height: BlockHeight) -> Self {
        let h = height.to_u32();
        let mut flags = Self::NONE;
        let mut i = 0;
        while i < Self::ACTIVATIONS.len() {
            let (activation_height, bits) = Self::ACTIVATIONS[i];
            if h >= activation_height {
                flags = flags.union(bits);
            }
            i += 1;
        }
        flags
    }
}

impl BitOr for ScriptFlags {
    type Output = Self;
    #[inline]
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for ScriptFlags {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl BitAnd for ScriptFlags {
    type Output = Self;
    #[inline]
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl Not for ScriptFlags {
    type Output = Self;
    #[inline]
    fn not(self) -> Self {
        Self(!self.0)
    }
}

impl Sub for ScriptFlags {
    type Output = Self;
    /// Flag-set subtraction: bits in `self` not present in `rhs`.
    #[inline]
    fn sub(self, rhs: Self) -> Self {
        Self(self.0 & !rhs.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_contains_nothing() {
        assert!(!ScriptFlags::NONE.contains(ScriptFlags::P2SH));
        assert!(ScriptFlags::NONE.contains(ScriptFlags::NONE));
    }

    #[test]
    fn union_then_contains() {
        let f = ScriptFlags::P2SH | ScriptFlags::DERSIG;
        assert!(f.contains(ScriptFlags::P2SH));
        assert!(f.contains(ScriptFlags::DERSIG));
        assert!(!f.contains(ScriptFlags::WITNESS));
    }

    #[test]
    fn subtract_clears_bit() {
        let f = ScriptFlags::P2SH | ScriptFlags::DERSIG;
        let g = f - ScriptFlags::P2SH;
        assert!(!g.contains(ScriptFlags::P2SH));
        assert!(g.contains(ScriptFlags::DERSIG));
    }

    #[test]
    fn for_height_genesis_is_none() {
        assert_eq!(
            ScriptFlags::for_height(BlockHeight::new(0)),
            ScriptFlags::NONE
        );
    }

    #[test]
    fn for_height_after_p2sh_includes_p2sh() {
        let f = ScriptFlags::for_height(BlockHeight::new(200_000));
        assert!(f.contains(ScriptFlags::P2SH));
        assert!(!f.contains(ScriptFlags::DERSIG));
    }

    #[test]
    fn for_height_post_taproot_includes_everything() {
        let f = ScriptFlags::for_height(BlockHeight::new(800_000));
        for bit in [
            ScriptFlags::P2SH,
            ScriptFlags::DERSIG,
            ScriptFlags::CHECKLOCKTIMEVERIFY,
            ScriptFlags::CHECKSEQUENCEVERIFY,
            ScriptFlags::WITNESS,
            ScriptFlags::NULLDUMMY,
            ScriptFlags::TAPROOT,
        ] {
            assert!(f.contains(bit), "missing flag at height 800_000");
        }
    }

    #[test]
    fn bits_roundtrip() {
        let raw = 0x1234_5678;
        assert_eq!(ScriptFlags::from_bits(raw).bits(), raw);
    }
}
