//! `ScriptReader` — slice-cursor over a script's bytes.
//!
//! The interpreter advances through a script by repeatedly fetching one
//! "step" — an opcode byte plus, for push opcodes, the data it pushes.
//! All bounds checks are the borrow checker's: we never store a raw pointer
//! past the end of the slice.

use crate::script::error::ScriptError;
use crate::script::opcodes::{Opcode, OpcodeFlags};

/// One decoded step of a script: the opcode plus, for push opcodes, the
/// raw data bytes that follow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Step<'a> {
    /// The decoded opcode.
    pub opcode: Opcode,
    /// Precomputed property flags resolved from the raw wire byte.
    pub flags: OpcodeFlags,
    /// For push opcodes, the bytes pushed. Empty for non-push opcodes and
    /// for `OP_0`/`OP_1NEGATE`/`OP_N` (those produce constants without
    /// reading from the script body).
    pub data: &'a [u8],
}

/// Borrowed cursor over a script.
#[derive(Debug, Clone, Copy)]
pub struct ScriptReader<'a> {
    full: &'a [u8],
    cursor: &'a [u8],
}

impl<'a> ScriptReader<'a> {
    /// Wrap a script slice. The cursor starts at offset 0.
    #[must_use]
    pub const fn new(script: &'a [u8]) -> Self {
        Self {
            full: script,
            cursor: script,
        }
    }

    /// `true` if the cursor is at end of script.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cursor.is_empty()
    }

    /// Byte offset of the cursor from the start of the script.
    #[inline]
    #[must_use]
    pub fn position(&self) -> usize {
        self.full.len() - self.cursor.len()
    }

    /// Decode the next opcode and, for push opcodes, the data that follows.
    ///
    /// Returns `Ok(None)` at end of script. Returns `Err` if a push opcode
    /// declares more data than is available.
    ///
    /// # Errors
    /// `BadPushLength` if a push opcode runs past end of script or declares
    /// a length too large to be a `usize`.
    pub fn next_step(&mut self) -> Result<Option<Step<'a>>, ScriptError> {
        let Some((&op_byte, rest)) = self.cursor.split_first() else {
            return Ok(None);
        };
        self.cursor = rest;

        let opcode = Opcode::from_byte(op_byte);
        let data = match opcode {
            Opcode::PushBytes(n) => self.take(n.into())?,
            Opcode::PushData1 => {
                let n = self.take_u8()? as usize;
                self.take(n)?
            }
            Opcode::PushData2 => {
                let n = self.take_u16_le()? as usize;
                self.take(n)?
            }
            Opcode::PushData4 => {
                // u32 may overflow usize on 16-bit platforms; we don't run
                // there, but be conservative anyway.
                let n =
                    usize::try_from(self.take_u32_le()?).map_err(|_| ScriptError::BadPushLength)?;
                self.take(n)?
            }
            _ => &[],
        };

        Ok(Some(Step {
            opcode,
            flags: Opcode::flags_for_byte(op_byte),
            data,
        }))
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ScriptError> {
        if self.cursor.len() < n {
            return Err(ScriptError::BadPushLength);
        }
        let (head, rest) = self.cursor.split_at(n);
        self.cursor = rest;
        Ok(head)
    }

    fn take_u8(&mut self) -> Result<u8, ScriptError> {
        let bytes = self.take(1)?;
        Ok(bytes[0])
    }

    fn take_u16_le(&mut self) -> Result<u16, ScriptError> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn take_u32_le(&mut self) -> Result<u32, ScriptError> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_script_returns_none() {
        let mut r = ScriptReader::new(&[]);
        assert!(r.next_step().expect("no error").is_none());
        assert!(r.is_empty());
    }

    #[test]
    fn op0_then_dup() {
        // 0x00 0x76  →  OP_0, OP_DUP
        let mut r = ScriptReader::new(&[0x00, 0x76]);
        let s1 = r.next_step().expect("no err").expect("step");
        assert_eq!(s1.opcode, Opcode::Op0);
        assert!(s1.data.is_empty());
        let s2 = r.next_step().expect("no err").expect("step");
        assert_eq!(s2.opcode, Opcode::Dup);
        assert!(r.next_step().expect("no err").is_none());
    }

    #[test]
    fn push_bytes_decodes_data() {
        // 0x03 0xaa 0xbb 0xcc  →  push three bytes
        let mut r = ScriptReader::new(&[0x03, 0xaa, 0xbb, 0xcc]);
        let s = r.next_step().expect("no err").expect("step");
        assert_eq!(s.opcode, Opcode::PushBytes(3));
        assert_eq!(s.data, &[0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn push_bytes_truncated_is_bad_push_length() {
        // 0x03 0xaa  →  declares 3, only 1 follows
        let mut r = ScriptReader::new(&[0x03, 0xaa]);
        assert!(matches!(r.next_step(), Err(ScriptError::BadPushLength)));
    }

    #[test]
    fn pushdata1_decodes() {
        // 0x4c 0x02 0xab 0xcd  →  OP_PUSHDATA1 length=2 data=[ab, cd]
        let mut r = ScriptReader::new(&[0x4c, 0x02, 0xab, 0xcd]);
        let s = r.next_step().expect("no err").expect("step");
        assert_eq!(s.opcode, Opcode::PushData1);
        assert_eq!(s.data, &[0xab, 0xcd]);
    }

    #[test]
    fn pushdata1_truncated() {
        // OP_PUSHDATA1 with no length byte
        let mut r = ScriptReader::new(&[0x4c]);
        assert!(matches!(r.next_step(), Err(ScriptError::BadPushLength)));
        // OP_PUSHDATA1 length=5 but only 2 bytes follow
        let mut r = ScriptReader::new(&[0x4c, 0x05, 0x01, 0x02]);
        assert!(matches!(r.next_step(), Err(ScriptError::BadPushLength)));
    }

    #[test]
    fn pushdata2_decodes() {
        // OP_PUSHDATA2 length=3 (LE) then data
        let mut r = ScriptReader::new(&[0x4d, 0x03, 0x00, 0x11, 0x22, 0x33]);
        let s = r.next_step().expect("no err").expect("step");
        assert_eq!(s.opcode, Opcode::PushData2);
        assert_eq!(s.data, &[0x11, 0x22, 0x33]);
    }

    #[test]
    fn pushdata4_decodes() {
        // OP_PUSHDATA4 length=2 (LE u32) then data
        let mut r = ScriptReader::new(&[0x4e, 0x02, 0x00, 0x00, 0x00, 0xde, 0xad]);
        let s = r.next_step().expect("no err").expect("step");
        assert_eq!(s.opcode, Opcode::PushData4);
        assert_eq!(s.data, &[0xde, 0xad]);
    }

    #[test]
    fn position_advances() {
        let mut r = ScriptReader::new(&[0x00, 0x00, 0x00]);
        assert_eq!(r.position(), 0);
        r.next_step().expect("no err");
        assert_eq!(r.position(), 1);
        r.next_step().expect("no err");
        assert_eq!(r.position(), 2);
    }

    #[test]
    fn invalid_opcode_byte_decodes_to_invalid_variant() {
        // 0xff is not a defined opcode; the reader still produces a step.
        // The interpreter is responsible for failing on Opcode::Invalid.
        let mut r = ScriptReader::new(&[0xff]);
        let s = r.next_step().expect("no err").expect("step");
        assert_eq!(s.opcode, Opcode::Invalid(0xff));
    }
}
