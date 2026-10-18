use std::borrow::Cow;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindAndDelete {
    pattern: Vec<u8>,
}

impl FindAndDelete {
    #[must_use]
    pub fn for_push(data: &[u8]) -> Self {
        let mut pattern = Vec::with_capacity(data.len() + 5);
        match data.len() {
            len @ 0..=0x4b => pattern.push(u8::try_from(len).unwrap_or_default()),
            len @ 0x4c..=0xff => {
                pattern.push(0x4c);
                pattern.push(u8::try_from(len).unwrap_or_default());
            }
            len @ 0x100..=0xffff => {
                pattern.push(0x4d);
                pattern.extend_from_slice(&u16::try_from(len).unwrap_or_default().to_le_bytes());
            }
            len => {
                pattern.push(0x4e);
                pattern.extend_from_slice(&u32::try_from(len).unwrap_or(u32::MAX).to_le_bytes());
            }
        }
        pattern.extend_from_slice(data);
        Self { pattern }
    }

    #[must_use]
    pub fn apply<'s>(&self, script: &'s [u8]) -> Cow<'s, [u8]> {
        let mut result = Vec::new();
        let mut found = false;
        let mut pc = 0;
        let mut copied_from = 0;
        loop {
            result.extend_from_slice(&script[copied_from..pc]);
            while script[pc..].starts_with(&self.pattern) {
                pc += self.pattern.len();
                found = true;
            }
            copied_from = pc;
            match Self::op_len(&script[pc..]) {
                Some(len) => pc += len,
                None => break,
            }
        }
        if !found {
            return Cow::Borrowed(script);
        }
        result.extend_from_slice(&script[copied_from..]);
        Cow::Owned(result)
    }

    fn op_len(rest: &[u8]) -> Option<usize> {
        let (&op, tail) = rest.split_first()?;
        let (header, payload) = match op {
            0x00..=0x4b => (0, usize::from(op)),
            0x4c => (1, usize::from(*tail.first()?)),
            0x4d => (
                2,
                usize::from(u16::from_le_bytes(tail.get(..2)?.try_into().ok()?)),
            ),
            0x4e => (
                4,
                usize::try_from(u32::from_le_bytes(tail.get(..4)?.try_into().ok()?)).ok()?,
            ),
            _ => return Some(1),
        };
        let len = 1 + header + payload;
        (len <= rest.len()).then_some(len)
    }
}

#[cfg(test)]
#[path = "find_and_delete/tests.rs"]
mod tests;
