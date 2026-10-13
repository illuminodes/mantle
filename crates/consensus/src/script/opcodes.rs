//! Bitcoin script opcodes.
//!
//! Every consensus-defined opcode has its own variant. Unassigned bytes
//! (0xBA..=0xFF, all of which Core treats as `OP_INVALIDOPCODE`) collapse
//! into the single `Invalid(u8)` umbrella so the source isn't padded with
//! 70 dead names.
//!
//! `from_byte` is infallible: every `u8` maps somewhere. `to_byte` recovers
//! the wire byte, including the carried byte for `Invalid`.

/// A Bitcoin script opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[allow(clippy::upper_case_acronyms)] // names follow Bitcoin script convention
pub enum Opcode {
    // ── Push ────────────────────────────────────────────────────────────────
    /// `OP_0` / `OP_FALSE` — push the empty byte string.
    Op0 = 0x00,
    /// Push the next 1..=75 bytes literally. The discriminant is the byte
    /// count, so a 1-byte push is `PushBytes(1)` with wire byte 0x01.
    PushBytes(u8),
    /// `OP_PUSHDATA1` — next 1 byte is length, then that many bytes of data.
    PushData1 = 0x4c,
    /// `OP_PUSHDATA2` — next 2 bytes (LE) are length, then data.
    PushData2 = 0x4d,
    /// `OP_PUSHDATA4` — next 4 bytes (LE) are length, then data.
    PushData4 = 0x4e,
    /// `OP_1NEGATE` — push the value -1.
    Op1Negate = 0x4f,
    /// `OP_RESERVED` — fails if executed.
    OpReserved = 0x50,
    /// `OP_1` … `OP_16` — push the constant 1..=16. Wire bytes 0x51..=0x60.
    OpN(u8),

    // ── Control ─────────────────────────────────────────────────────────────
    Nop = 0x61,
    /// `OP_VER` — fails if executed.
    Ver = 0x62,
    If = 0x63,
    NotIf = 0x64,
    /// `OP_VERIF` — always fails, even when not executed.
    VerIf = 0x65,
    /// `OP_VERNOTIF` — always fails, even when not executed.
    VerNotIf = 0x66,
    Else = 0x67,
    EndIf = 0x68,
    Verify = 0x69,
    Return = 0x6a,

    // ── Stack ───────────────────────────────────────────────────────────────
    ToAltStack = 0x6b,
    FromAltStack = 0x6c,
    TwoDrop = 0x6d,
    TwoDup = 0x6e,
    ThreeDup = 0x6f,
    TwoOver = 0x70,
    TwoRot = 0x71,
    TwoSwap = 0x72,
    IfDup = 0x73,
    Depth = 0x74,
    Drop = 0x75,
    Dup = 0x76,
    Nip = 0x77,
    Over = 0x78,
    Pick = 0x79,
    Roll = 0x7a,
    Rot = 0x7b,
    Swap = 0x7c,
    Tuck = 0x7d,

    // ── Splice (mostly disabled) ────────────────────────────────────────────
    /// Disabled.
    Cat = 0x7e,
    /// Disabled.
    SubStr = 0x7f,
    /// Disabled.
    Left = 0x80,
    /// Disabled.
    Right = 0x81,
    Size = 0x82,

    // ── Bitwise (mostly disabled) ───────────────────────────────────────────
    /// Disabled.
    Invert = 0x83,
    /// Disabled.
    And = 0x84,
    /// Disabled.
    Or = 0x85,
    /// Disabled.
    Xor = 0x86,
    Equal = 0x87,
    EqualVerify = 0x88,
    /// Reserved (fails if executed).
    Reserved1 = 0x89,
    /// Reserved (fails if executed).
    Reserved2 = 0x8a,

    // ── Arithmetic ──────────────────────────────────────────────────────────
    OneAdd = 0x8b,
    OneSub = 0x8c,
    /// Disabled.
    TwoMul = 0x8d,
    /// Disabled.
    TwoDiv = 0x8e,
    Negate = 0x8f,
    Abs = 0x90,
    Not = 0x91,
    ZeroNotEqual = 0x92,
    Add = 0x93,
    Sub = 0x94,
    /// Disabled.
    Mul = 0x95,
    /// Disabled.
    Div = 0x96,
    /// Disabled.
    Mod = 0x97,
    /// Disabled.
    LShift = 0x98,
    /// Disabled.
    RShift = 0x99,
    BoolAnd = 0x9a,
    BoolOr = 0x9b,
    NumEqual = 0x9c,
    NumEqualVerify = 0x9d,
    NumNotEqual = 0x9e,
    LessThan = 0x9f,
    GreaterThan = 0xa0,
    LessThanOrEqual = 0xa1,
    GreaterThanOrEqual = 0xa2,
    Min = 0xa3,
    Max = 0xa4,
    Within = 0xa5,

    // ── Crypto ──────────────────────────────────────────────────────────────
    Ripemd160 = 0xa6,
    Sha1 = 0xa7,
    Sha256 = 0xa8,
    Hash160 = 0xa9,
    Hash256 = 0xaa,
    CodeSeparator = 0xab,
    CheckSig = 0xac,
    CheckSigVerify = 0xad,
    CheckMultiSig = 0xae,
    CheckMultiSigVerify = 0xaf,

    // ── Reserved / soft-fork hooks ──────────────────────────────────────────
    Nop1 = 0xb0,
    /// `OP_NOP2` — replaced by `OP_CHECKLOCKTIMEVERIFY` (BIP65).
    CheckLockTimeVerify = 0xb1,
    /// `OP_NOP3` — replaced by `OP_CHECKSEQUENCEVERIFY` (BIP112).
    CheckSequenceVerify = 0xb2,
    Nop4 = 0xb3,
    Nop5 = 0xb4,
    Nop6 = 0xb5,
    Nop7 = 0xb6,
    Nop8 = 0xb7,
    Nop9 = 0xb8,
    Nop10 = 0xb9,

    /// `OP_CHECKSIGADD` — BIP342. Wire byte 0xba.
    /// (Outside tapscript this byte is invalid; the variant exists so we don't
    /// have to reshape the enum when M3 lands.)
    CheckSigAdd = 0xba,

    /// Any wire byte that does not correspond to a defined opcode.
    /// Carries the byte so `to_byte` is total.
    Invalid(u8),
}

impl Opcode {
    /// Decode a wire byte. Total — every `u8` maps to exactly one variant.
    #[must_use]
    #[allow(clippy::too_many_lines)] // dispatch table; splitting would be worse
    pub const fn from_byte(byte: u8) -> Self {
        match byte {
            0x00 => Self::Op0,
            0x01..=0x4b => Self::PushBytes(byte),
            0x4c => Self::PushData1,
            0x4d => Self::PushData2,
            0x4e => Self::PushData4,
            0x4f => Self::Op1Negate,
            0x50 => Self::OpReserved,
            0x51..=0x60 => Self::OpN(byte - 0x50),
            0x61 => Self::Nop,
            0x62 => Self::Ver,
            0x63 => Self::If,
            0x64 => Self::NotIf,
            0x65 => Self::VerIf,
            0x66 => Self::VerNotIf,
            0x67 => Self::Else,
            0x68 => Self::EndIf,
            0x69 => Self::Verify,
            0x6a => Self::Return,
            0x6b => Self::ToAltStack,
            0x6c => Self::FromAltStack,
            0x6d => Self::TwoDrop,
            0x6e => Self::TwoDup,
            0x6f => Self::ThreeDup,
            0x70 => Self::TwoOver,
            0x71 => Self::TwoRot,
            0x72 => Self::TwoSwap,
            0x73 => Self::IfDup,
            0x74 => Self::Depth,
            0x75 => Self::Drop,
            0x76 => Self::Dup,
            0x77 => Self::Nip,
            0x78 => Self::Over,
            0x79 => Self::Pick,
            0x7a => Self::Roll,
            0x7b => Self::Rot,
            0x7c => Self::Swap,
            0x7d => Self::Tuck,
            0x7e => Self::Cat,
            0x7f => Self::SubStr,
            0x80 => Self::Left,
            0x81 => Self::Right,
            0x82 => Self::Size,
            0x83 => Self::Invert,
            0x84 => Self::And,
            0x85 => Self::Or,
            0x86 => Self::Xor,
            0x87 => Self::Equal,
            0x88 => Self::EqualVerify,
            0x89 => Self::Reserved1,
            0x8a => Self::Reserved2,
            0x8b => Self::OneAdd,
            0x8c => Self::OneSub,
            0x8d => Self::TwoMul,
            0x8e => Self::TwoDiv,
            0x8f => Self::Negate,
            0x90 => Self::Abs,
            0x91 => Self::Not,
            0x92 => Self::ZeroNotEqual,
            0x93 => Self::Add,
            0x94 => Self::Sub,
            0x95 => Self::Mul,
            0x96 => Self::Div,
            0x97 => Self::Mod,
            0x98 => Self::LShift,
            0x99 => Self::RShift,
            0x9a => Self::BoolAnd,
            0x9b => Self::BoolOr,
            0x9c => Self::NumEqual,
            0x9d => Self::NumEqualVerify,
            0x9e => Self::NumNotEqual,
            0x9f => Self::LessThan,
            0xa0 => Self::GreaterThan,
            0xa1 => Self::LessThanOrEqual,
            0xa2 => Self::GreaterThanOrEqual,
            0xa3 => Self::Min,
            0xa4 => Self::Max,
            0xa5 => Self::Within,
            0xa6 => Self::Ripemd160,
            0xa7 => Self::Sha1,
            0xa8 => Self::Sha256,
            0xa9 => Self::Hash160,
            0xaa => Self::Hash256,
            0xab => Self::CodeSeparator,
            0xac => Self::CheckSig,
            0xad => Self::CheckSigVerify,
            0xae => Self::CheckMultiSig,
            0xaf => Self::CheckMultiSigVerify,
            0xb0 => Self::Nop1,
            0xb1 => Self::CheckLockTimeVerify,
            0xb2 => Self::CheckSequenceVerify,
            0xb3 => Self::Nop4,
            0xb4 => Self::Nop5,
            0xb5 => Self::Nop6,
            0xb6 => Self::Nop7,
            0xb7 => Self::Nop8,
            0xb8 => Self::Nop9,
            0xb9 => Self::Nop10,
            0xba => Self::CheckSigAdd,
            other => Self::Invalid(other),
        }
    }

    /// Recover the wire byte. Total inverse of `from_byte` modulo the
    /// `PushBytes`/`OpN`/`Invalid` carriers.
    #[must_use]
    #[allow(clippy::too_many_lines)] // dispatch table; splitting would be worse
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::Op0 => 0x00,
            Self::PushBytes(n) => n,
            Self::PushData1 => 0x4c,
            Self::PushData2 => 0x4d,
            Self::PushData4 => 0x4e,
            Self::Op1Negate => 0x4f,
            Self::OpReserved => 0x50,
            Self::OpN(n) => 0x50 + n,
            Self::Nop => 0x61,
            Self::Ver => 0x62,
            Self::If => 0x63,
            Self::NotIf => 0x64,
            Self::VerIf => 0x65,
            Self::VerNotIf => 0x66,
            Self::Else => 0x67,
            Self::EndIf => 0x68,
            Self::Verify => 0x69,
            Self::Return => 0x6a,
            Self::ToAltStack => 0x6b,
            Self::FromAltStack => 0x6c,
            Self::TwoDrop => 0x6d,
            Self::TwoDup => 0x6e,
            Self::ThreeDup => 0x6f,
            Self::TwoOver => 0x70,
            Self::TwoRot => 0x71,
            Self::TwoSwap => 0x72,
            Self::IfDup => 0x73,
            Self::Depth => 0x74,
            Self::Drop => 0x75,
            Self::Dup => 0x76,
            Self::Nip => 0x77,
            Self::Over => 0x78,
            Self::Pick => 0x79,
            Self::Roll => 0x7a,
            Self::Rot => 0x7b,
            Self::Swap => 0x7c,
            Self::Tuck => 0x7d,
            Self::Cat => 0x7e,
            Self::SubStr => 0x7f,
            Self::Left => 0x80,
            Self::Right => 0x81,
            Self::Size => 0x82,
            Self::Invert => 0x83,
            Self::And => 0x84,
            Self::Or => 0x85,
            Self::Xor => 0x86,
            Self::Equal => 0x87,
            Self::EqualVerify => 0x88,
            Self::Reserved1 => 0x89,
            Self::Reserved2 => 0x8a,
            Self::OneAdd => 0x8b,
            Self::OneSub => 0x8c,
            Self::TwoMul => 0x8d,
            Self::TwoDiv => 0x8e,
            Self::Negate => 0x8f,
            Self::Abs => 0x90,
            Self::Not => 0x91,
            Self::ZeroNotEqual => 0x92,
            Self::Add => 0x93,
            Self::Sub => 0x94,
            Self::Mul => 0x95,
            Self::Div => 0x96,
            Self::Mod => 0x97,
            Self::LShift => 0x98,
            Self::RShift => 0x99,
            Self::BoolAnd => 0x9a,
            Self::BoolOr => 0x9b,
            Self::NumEqual => 0x9c,
            Self::NumEqualVerify => 0x9d,
            Self::NumNotEqual => 0x9e,
            Self::LessThan => 0x9f,
            Self::GreaterThan => 0xa0,
            Self::LessThanOrEqual => 0xa1,
            Self::GreaterThanOrEqual => 0xa2,
            Self::Min => 0xa3,
            Self::Max => 0xa4,
            Self::Within => 0xa5,
            Self::Ripemd160 => 0xa6,
            Self::Sha1 => 0xa7,
            Self::Sha256 => 0xa8,
            Self::Hash160 => 0xa9,
            Self::Hash256 => 0xaa,
            Self::CodeSeparator => 0xab,
            Self::CheckSig => 0xac,
            Self::CheckSigVerify => 0xad,
            Self::CheckMultiSig => 0xae,
            Self::CheckMultiSigVerify => 0xaf,
            Self::Nop1 => 0xb0,
            Self::CheckLockTimeVerify => 0xb1,
            Self::CheckSequenceVerify => 0xb2,
            Self::Nop4 => 0xb3,
            Self::Nop5 => 0xb4,
            Self::Nop6 => 0xb5,
            Self::Nop7 => 0xb6,
            Self::Nop8 => 0xb7,
            Self::Nop9 => 0xb8,
            Self::Nop10 => 0xb9,
            Self::CheckSigAdd => 0xba,
            Self::Invalid(b) => b,
        }
    }

    /// Diagnostic name. Stable identifier suitable for logging and error messages.
    #[must_use]
    #[allow(clippy::too_many_lines)] // dispatch table; splitting would be worse
    pub const fn name(self) -> &'static str {
        match self {
            Self::Op0 => "OP_0",
            Self::PushBytes(_) => "OP_PUSHBYTES",
            Self::PushData1 => "OP_PUSHDATA1",
            Self::PushData2 => "OP_PUSHDATA2",
            Self::PushData4 => "OP_PUSHDATA4",
            Self::Op1Negate => "OP_1NEGATE",
            Self::OpReserved => "OP_RESERVED",
            Self::OpN(_) => "OP_N",
            Self::Nop => "OP_NOP",
            Self::Ver => "OP_VER",
            Self::If => "OP_IF",
            Self::NotIf => "OP_NOTIF",
            Self::VerIf => "OP_VERIF",
            Self::VerNotIf => "OP_VERNOTIF",
            Self::Else => "OP_ELSE",
            Self::EndIf => "OP_ENDIF",
            Self::Verify => "OP_VERIFY",
            Self::Return => "OP_RETURN",
            Self::ToAltStack => "OP_TOALTSTACK",
            Self::FromAltStack => "OP_FROMALTSTACK",
            Self::TwoDrop => "OP_2DROP",
            Self::TwoDup => "OP_2DUP",
            Self::ThreeDup => "OP_3DUP",
            Self::TwoOver => "OP_2OVER",
            Self::TwoRot => "OP_2ROT",
            Self::TwoSwap => "OP_2SWAP",
            Self::IfDup => "OP_IFDUP",
            Self::Depth => "OP_DEPTH",
            Self::Drop => "OP_DROP",
            Self::Dup => "OP_DUP",
            Self::Nip => "OP_NIP",
            Self::Over => "OP_OVER",
            Self::Pick => "OP_PICK",
            Self::Roll => "OP_ROLL",
            Self::Rot => "OP_ROT",
            Self::Swap => "OP_SWAP",
            Self::Tuck => "OP_TUCK",
            Self::Cat => "OP_CAT",
            Self::SubStr => "OP_SUBSTR",
            Self::Left => "OP_LEFT",
            Self::Right => "OP_RIGHT",
            Self::Size => "OP_SIZE",
            Self::Invert => "OP_INVERT",
            Self::And => "OP_AND",
            Self::Or => "OP_OR",
            Self::Xor => "OP_XOR",
            Self::Equal => "OP_EQUAL",
            Self::EqualVerify => "OP_EQUALVERIFY",
            Self::Reserved1 => "OP_RESERVED1",
            Self::Reserved2 => "OP_RESERVED2",
            Self::OneAdd => "OP_1ADD",
            Self::OneSub => "OP_1SUB",
            Self::TwoMul => "OP_2MUL",
            Self::TwoDiv => "OP_2DIV",
            Self::Negate => "OP_NEGATE",
            Self::Abs => "OP_ABS",
            Self::Not => "OP_NOT",
            Self::ZeroNotEqual => "OP_0NOTEQUAL",
            Self::Add => "OP_ADD",
            Self::Sub => "OP_SUB",
            Self::Mul => "OP_MUL",
            Self::Div => "OP_DIV",
            Self::Mod => "OP_MOD",
            Self::LShift => "OP_LSHIFT",
            Self::RShift => "OP_RSHIFT",
            Self::BoolAnd => "OP_BOOLAND",
            Self::BoolOr => "OP_BOOLOR",
            Self::NumEqual => "OP_NUMEQUAL",
            Self::NumEqualVerify => "OP_NUMEQUALVERIFY",
            Self::NumNotEqual => "OP_NUMNOTEQUAL",
            Self::LessThan => "OP_LESSTHAN",
            Self::GreaterThan => "OP_GREATERTHAN",
            Self::LessThanOrEqual => "OP_LESSTHANOREQUAL",
            Self::GreaterThanOrEqual => "OP_GREATERTHANOREQUAL",
            Self::Min => "OP_MIN",
            Self::Max => "OP_MAX",
            Self::Within => "OP_WITHIN",
            Self::Ripemd160 => "OP_RIPEMD160",
            Self::Sha1 => "OP_SHA1",
            Self::Sha256 => "OP_SHA256",
            Self::Hash160 => "OP_HASH160",
            Self::Hash256 => "OP_HASH256",
            Self::CodeSeparator => "OP_CODESEPARATOR",
            Self::CheckSig => "OP_CHECKSIG",
            Self::CheckSigVerify => "OP_CHECKSIGVERIFY",
            Self::CheckMultiSig => "OP_CHECKMULTISIG",
            Self::CheckMultiSigVerify => "OP_CHECKMULTISIGVERIFY",
            Self::Nop1 => "OP_NOP1",
            Self::CheckLockTimeVerify => "OP_CHECKLOCKTIMEVERIFY",
            Self::CheckSequenceVerify => "OP_CHECKSEQUENCEVERIFY",
            Self::Nop4 => "OP_NOP4",
            Self::Nop5 => "OP_NOP5",
            Self::Nop6 => "OP_NOP6",
            Self::Nop7 => "OP_NOP7",
            Self::Nop8 => "OP_NOP8",
            Self::Nop9 => "OP_NOP9",
            Self::Nop10 => "OP_NOP10",
            Self::CheckSigAdd => "OP_CHECKSIGADD",
            Self::Invalid(_) => "OP_INVALIDOPCODE",
        }
    }

    /// `true` if this opcode is a push-type opcode for `SIGPUSHONLY` purposes.
    ///
    /// Core's `IsPushOnly` checks `opcode <= OP_16` (0x60), which includes
    /// `OP_RESERVED` (0x50). Execution of `OP_RESERVED` always fails, so this
    /// is irrelevant in practice — the scriptSig would fail before the P2SH
    /// special-case runs — but we must match Core's byte-range semantics.
    #[must_use]
    pub const fn is_push(self) -> bool {
        matches!(
            self,
            Self::Op0
                | Self::PushBytes(_)
                | Self::PushData1
                | Self::PushData2
                | Self::PushData4
                | Self::Op1Negate
                | Self::OpReserved
                | Self::OpN(_)
        )
    }

    /// `true` if this opcode is consensus-disabled. Executing one fails the
    /// script with `ScriptError::DisabledOpcode`.
    ///
    /// Note: the disabled-list is checked even inside an unexecuted branch
    /// for the splice/bitwise/`OP_VERIF`/`OP_VERNOTIF` group; those are
    /// handled by the interpreter's pre-scan, not here.
    #[must_use]
    pub const fn is_disabled(self) -> bool {
        matches!(
            self,
            Self::Cat
                | Self::SubStr
                | Self::Left
                | Self::Right
                | Self::Invert
                | Self::And
                | Self::Or
                | Self::Xor
                | Self::TwoMul
                | Self::TwoDiv
                | Self::Mul
                | Self::Div
                | Self::Mod
                | Self::LShift
                | Self::RShift
        )
    }

    /// `true` if this opcode is one of the upgrade-reserved NOPs (`OP_NOP1`,
    /// `OP_NOP4`..`OP_NOP10`). `OP_NOP` (0x61) is *not* upgrade-reserved.
    #[must_use]
    pub const fn is_upgradable_nop(self) -> bool {
        matches!(
            self,
            Self::Nop1
                | Self::Nop4
                | Self::Nop5
                | Self::Nop6
                | Self::Nop7
                | Self::Nop8
                | Self::Nop9
                | Self::Nop10
        )
    }

    /// `true` if this opcode is an `OP_SUCCESSx` in BIP342 tapscript.
    ///
    /// When any of these bytes appear in a tapscript, the *entire script*
    /// succeeds immediately — they are not executed. This is the forward-compat
    /// mechanism that lets future soft-forks assign meaning to these bytes.
    ///
    /// Set per BIP342 §"Rules for tapscript" (decimal 80, 98, 126-129,
    /// 131-134, 137, 138, 141, 142, 149-153, 187-254):
    /// - `0x50` `OP_RESERVED`
    /// - `0x62` `OP_VER`
    /// - `0x7e..=0x81` (CAT, SUBSTR, LEFT, RIGHT)
    /// - `0x83..=0x86` (INVERT, AND, OR, XOR)
    /// - `0x89..=0x8a` (RESERVED1, RESERVED2)
    /// - `0x8d..=0x8e` (2MUL, 2DIV)
    /// - `0x95..=0x99` (MUL, DIV, MOD, LSHIFT, RSHIFT)
    /// - `0xbb..=0xfe` (undefined range)
    ///
    /// `OP_CHECKSIGADD` (0xba) is NOT an `OP_SUCCESSx` — it is a defined
    /// tapscript opcode.
    #[must_use]
    pub const fn is_tapscript_success(self) -> bool {
        let b = self.to_byte();
        matches!(b,
            0x50
            | 0x62
            | 0x7e..=0x81
            | 0x83..=0x86
            | 0x89..=0x8a
            | 0x8d..=0x8e
            | 0x95..=0x99
            | 0xbb..=0xfe
        )
    }

    // ── Precomputed per-byte flag table ────────────────────────────────

    /// Bit 0: counts toward op limit (non-push, byte > 0x60).
    /// Bit 1: is `VerIf` (0x65) or `VerNotIf` (0x66).
    const FLAGS: [u8; 256] = {
        let mut t = [0u8; 256];
        let mut b = 0x61u16;
        while b <= 0xFF {
            t[b as usize] |= 1;
            b += 1;
        }
        t[0x65] |= 2;
        t[0x66] |= 2;
        t
    };

    /// Look up the precomputed flags for a raw opcode byte.
    #[inline]
    #[must_use]
    pub const fn flags_for_byte(byte: u8) -> OpcodeFlags {
        OpcodeFlags(Self::FLAGS[byte as usize])
    }
}

/// Precomputed opcode property flags — resolved once from the raw byte in
/// `ScriptReader::next_step`, then queried in the interpreter step loop
/// without calling `to_byte()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpcodeFlags(u8);

impl OpcodeFlags {
    /// `true` if this opcode counts toward the 201-op-per-script limit.
    #[inline]
    #[must_use]
    pub const fn counts_toward_op_limit(self) -> bool {
        self.0 & 1 != 0
    }

    /// `true` if this is `OP_VERIF` or `OP_VERNOTIF`.
    #[inline]
    #[must_use]
    pub const fn is_verif_class(self) -> bool {
        self.0 & 2 != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_to_byte_roundtrip_total() {
        for byte in 0u8..=0xff {
            let op = Opcode::from_byte(byte);
            assert_eq!(
                op.to_byte(),
                byte,
                "roundtrip failed for byte {byte:#04x} → {op:?}"
            );
        }
    }

    #[test]
    fn push_bytes_carries_length() {
        for n in 1u8..=0x4b {
            let op = Opcode::from_byte(n);
            assert_eq!(op, Opcode::PushBytes(n));
        }
    }

    #[test]
    fn op_n_decodes_correctly() {
        for k in 1u8..=16 {
            let op = Opcode::from_byte(0x50 + k);
            assert_eq!(op, Opcode::OpN(k));
            assert_eq!(op.to_byte(), 0x50 + k);
        }
    }

    #[test]
    fn invalid_tail() {
        for byte in 0xbb..=0xffu8 {
            assert_eq!(Opcode::from_byte(byte), Opcode::Invalid(byte));
        }
    }

    #[test]
    fn pushes_are_pushes() {
        assert!(Opcode::Op0.is_push());
        assert!(Opcode::Op1Negate.is_push());
        assert!(Opcode::PushBytes(20).is_push());
        assert!(Opcode::PushData1.is_push());
        assert!(Opcode::OpN(7).is_push());
        assert!(!Opcode::Dup.is_push());
        assert!(!Opcode::CheckSig.is_push());
    }

    #[test]
    fn disabled_set() {
        for op in [
            Opcode::Cat,
            Opcode::SubStr,
            Opcode::Left,
            Opcode::Right,
            Opcode::Invert,
            Opcode::And,
            Opcode::Or,
            Opcode::Xor,
            Opcode::TwoMul,
            Opcode::TwoDiv,
            Opcode::Mul,
            Opcode::Div,
            Opcode::Mod,
            Opcode::LShift,
            Opcode::RShift,
        ] {
            assert!(op.is_disabled(), "{} should be disabled", op.name());
        }
        assert!(!Opcode::Add.is_disabled());
        assert!(!Opcode::CheckSig.is_disabled());
    }

    #[test]
    fn upgradable_nops() {
        assert!(!Opcode::Nop.is_upgradable_nop());
        for op in [
            Opcode::Nop1,
            Opcode::Nop4,
            Opcode::Nop5,
            Opcode::Nop6,
            Opcode::Nop7,
            Opcode::Nop8,
            Opcode::Nop9,
            Opcode::Nop10,
        ] {
            assert!(op.is_upgradable_nop());
        }
    }

    #[test]
    fn names_dont_panic() {
        for byte in 0u8..=0xff {
            let _ = Opcode::from_byte(byte).name();
        }
    }
}
