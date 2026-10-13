#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Op {
    Connect = 0,
    LinkTimeout = 1,
    Send = 2,
    Recv = 3,
    Close = 4,
    Tick = 0xff,
}

impl Op {
    #[inline]
    #[must_use]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Connect),
            1 => Some(Self::LinkTimeout),
            2 => Some(Self::Send),
            3 => Some(Self::Recv),
            4 => Some(Self::Close),
            0xff => Some(Self::Tick),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CqeData {
    pub slot: u16,
    pub generation: u16,
    pub op: Op,
}

impl CqeData {
    #[inline]
    #[must_use]
    pub fn encode(slot: u16, generation: u16, op: Op) -> u64 {
        (u64::from(slot) << 16) | (u64::from(generation) << 32) | (op as u64)
    }

    #[inline]
    #[must_use]
    pub fn decode(raw: u64) -> Self {
        #[allow(clippy::cast_possible_truncation)]
        let op_byte = (raw & 0xff) as u8;
        #[allow(clippy::cast_possible_truncation)]
        let slot = ((raw >> 16) & 0xffff) as u16;
        #[allow(clippy::cast_possible_truncation)]
        let generation = ((raw >> 32) & 0xffff) as u16;
        Self {
            slot,
            generation,
            op: Op::from_u8(op_byte).unwrap_or(Op::Close),
        }
    }

    #[inline]
    #[must_use]
    pub fn encode_send(slot: u16, generation: u16, send_seq: u16) -> u64 {
        Self::encode(slot, generation, Op::Send) | (u64::from(send_seq) << 48)
    }

    #[inline]
    #[must_use]
    pub fn decode_send_seq(raw: u64) -> u16 {
        #[allow(clippy::cast_possible_truncation)]
        { (raw >> 48) as u16 }
    }
}

#[inline]
#[must_use]
pub fn decode_cqe_buffer_id(flags: ququmatz::types::CqeFlags) -> Option<u16> {
    use ququmatz::types::CqeFlags;
    if flags.contains(CqeFlags::BUFFER) {
        #[allow(clippy::cast_possible_truncation)]
        Some((flags.bits() >> 16) as u16)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all_ops() {
        for op in [
            Op::Connect,
            Op::LinkTimeout,
            Op::Send,
            Op::Recv,
            Op::Close,
            Op::Tick,
        ] {
            let raw = CqeData::encode(42, 7, op);
            let d = CqeData::decode(raw);
            assert_eq!(d.slot, 42);
            assert_eq!(d.generation, 7);
            assert_eq!(d.op, op);
        }
    }

    #[test]
    fn roundtrip_extremes() {
        let raw = CqeData::encode(u16::MAX, u16::MAX, Op::Tick);
        let d = CqeData::decode(raw);
        assert_eq!(d.slot, u16::MAX);
        assert_eq!(d.generation, u16::MAX);
        assert_eq!(d.op, Op::Tick);

        let raw = CqeData::encode(0, 0, Op::Connect);
        let d = CqeData::decode(raw);
        assert_eq!(d.slot, 0);
        assert_eq!(d.generation, 0);
        assert_eq!(d.op, Op::Connect);
    }

    #[test]
    fn send_seq_roundtrip() {
        let raw = CqeData::encode_send(10, 20, 300);
        let d = CqeData::decode(raw);
        assert_eq!(d.slot, 10);
        assert_eq!(d.generation, 20);
        assert_eq!(d.op, Op::Send);
        assert_eq!(CqeData::decode_send_seq(raw), 300);
    }

    #[test]
    fn send_seq_max() {
        let raw = CqeData::encode_send(u16::MAX, u16::MAX, u16::MAX);
        let d = CqeData::decode(raw);
        assert_eq!(d.slot, u16::MAX);
        assert_eq!(d.generation, u16::MAX);
        assert_eq!(d.op, Op::Send);
        assert_eq!(CqeData::decode_send_seq(raw), u16::MAX);
    }

    #[test]
    fn no_field_overlap() {
        let raw = CqeData::encode(0x1234, 0x5678, Op::Recv);
        assert_eq!(raw & 0xff, Op::Recv as u64);
        assert_eq!((raw >> 16) & 0xffff, 0x1234);
        assert_eq!((raw >> 32) & 0xffff, 0x5678);
    }

    #[test]
    fn unknown_op_falls_back_to_close() {
        let raw = CqeData::encode(1, 2, Op::Connect);
        let tampered = (raw & !0xff) | 0x42;
        let d = CqeData::decode(tampered);
        assert_eq!(d.op, Op::Close);
    }
}
