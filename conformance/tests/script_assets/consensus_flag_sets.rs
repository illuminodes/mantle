//! The consensus flag combinations Core's script assets test iterates.

use mantle_consensus::script::ScriptFlags;

/// Every combination of the seven consensus flags in which WITNESS implies
/// P2SH and TAPROOT implies WITNESS.
pub struct ConsensusFlagSets(Vec<ScriptFlags>);

impl ConsensusFlagSets {
    const BITS: [ScriptFlags; 7] = [
        ScriptFlags::P2SH,
        ScriptFlags::DERSIG,
        ScriptFlags::NULLDUMMY,
        ScriptFlags::CHECKLOCKTIMEVERIFY,
        ScriptFlags::CHECKSEQUENCEVERIFY,
        ScriptFlags::WITNESS,
        ScriptFlags::TAPROOT,
    ];

    pub fn all() -> Self {
        let mut sets = Vec::new();
        for mask in 0u32..128 {
            let mut flags = ScriptFlags::NONE;
            for (i, bit) in Self::BITS.iter().enumerate() {
                if mask & (1 << i) != 0 {
                    flags |= *bit;
                }
            }
            if flags.contains(ScriptFlags::WITNESS) && !flags.contains(ScriptFlags::P2SH) {
                continue;
            }
            if flags.contains(ScriptFlags::TAPROOT) && !flags.contains(ScriptFlags::WITNESS) {
                continue;
            }
            sets.push(flags);
        }
        Self(sets)
    }

    pub fn iter(&self) -> impl Iterator<Item = ScriptFlags> + '_ {
        self.0.iter().copied()
    }

    /// Parse Core's comma-separated flag names. Names outside the
    /// consensus set (policy flags) are ignored, as Core's test only
    /// combines consensus flags with them.
    pub fn parse(names: &str) -> ScriptFlags {
        names
            .split(',')
            .filter(|n| !n.is_empty())
            .fold(ScriptFlags::NONE, |acc, name| {
                acc | match name {
                    "P2SH" => ScriptFlags::P2SH,
                    "DERSIG" => ScriptFlags::DERSIG,
                    "NULLDUMMY" => ScriptFlags::NULLDUMMY,
                    "CHECKLOCKTIMEVERIFY" => ScriptFlags::CHECKLOCKTIMEVERIFY,
                    "CHECKSEQUENCEVERIFY" => ScriptFlags::CHECKSEQUENCEVERIFY,
                    "WITNESS" => ScriptFlags::WITNESS,
                    "TAPROOT" => ScriptFlags::TAPROOT,
                    _ => ScriptFlags::NONE,
                }
            })
    }
}
