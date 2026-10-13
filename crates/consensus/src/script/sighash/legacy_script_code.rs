use mantle::codec::{Encode, VarInt};

const OP_CODESEPARATOR: u8 = 0xab;

pub(super) struct LegacyScriptCode<'s> {
    script: &'s [u8],
}

impl<'s> LegacyScriptCode<'s> {
    pub(super) const fn new(script: &'s [u8]) -> Self {
        Self { script }
    }

    pub(super) fn encode(&self, buf: &mut Vec<u8>) {
        let separators = self.separator_ends();
        let _ = VarInt::from(self.script.len() - separators.len()).encode(buf);
        let mut segment_start = 0;
        for end in separators {
            buf.extend_from_slice(&self.script[segment_start..end - 1]);
            segment_start = end;
        }
        buf.extend_from_slice(&self.script[segment_start..]);
    }

    fn separator_ends(&self) -> Vec<usize> {
        let mut ends = Vec::new();
        let mut pc = 0;
        while let Some(next) = Self::next_op(self.script, pc) {
            if self.script[pc] == OP_CODESEPARATOR {
                ends.push(next);
            }
            pc = next;
        }
        ends
    }

    fn next_op(script: &[u8], pc: usize) -> Option<usize> {
        let &opcode = script.get(pc)?;
        let after_op = pc + 1;
        let (data_start, size) = match opcode {
            0x00..=0x4b => (after_op, usize::from(opcode)),
            0x4c => (after_op + 1, usize::from(*script.get(after_op)?)),
            0x4d => {
                let b = script.get(after_op..after_op + 2)?;
                (after_op + 2, usize::from(u16::from_le_bytes([b[0], b[1]])))
            }
            0x4e => {
                let b = script.get(after_op..after_op + 4)?;
                (
                    after_op + 4,
                    usize::try_from(u32::from_le_bytes([b[0], b[1], b[2], b[3]])).ok()?,
                )
            }
            _ => (after_op, 0),
        };
        let next = data_start.checked_add(size)?;
        (next <= script.len()).then_some(next)
    }
}

#[cfg(test)]
#[path = "legacy_script_code/tests.rs"]
mod tests;
