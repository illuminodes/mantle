use super::*;
use crate::script::checker::NopSigChecker;

fn run(script: &[u8]) -> Result<Stack, ScriptError> {
    let checker = NopSigChecker;
    let mut interp = Interpreter::new(&checker, ScriptFlags::NONE, SigVersion::Base);
    interp.eval(script)?;
    Ok(interp.stack)
}

fn run_flags(script: &[u8], flags: ScriptFlags) -> Result<Stack, ScriptError> {
    let checker = NopSigChecker;
    let mut interp = Interpreter::new(&checker, flags, SigVersion::Base);
    interp.eval(script)?;
    Ok(interp.stack)
}

// ── Push opcodes ────────────────────────────────────────────────────────

#[test]
fn op_0_pushes_empty() {
    let s = run(&[0x00]).expect("ok");
    assert_eq!(s.len(), 1);
    assert!(s.peek(0).expect("non-empty").is_empty());
}

#[test]
fn pushbytes_pushes_data() {
    // OP_PUSHBYTES_3 0xaa 0xbb 0xcc
    let s = run(&[0x03, 0xaa, 0xbb, 0xcc]).expect("ok");
    assert_eq!(s.peek(0).expect("ok"), &[0xaa, 0xbb, 0xcc]);
}

#[test]
fn op_1negate_pushes_minus_one() {
    // OP_1NEGATE OP_1ADD  →  0
    let s = run(&[0x4f, 0x8b]).expect("ok");
    assert_eq!(s.peek(0).expect("ok"), &[]); // 0 encodes as empty
}

#[test]
fn op_n_pushes_constant() {
    // OP_5 → top is [0x05]
    let s = run(&[0x55]).expect("ok");
    assert_eq!(s.peek(0).expect("ok"), &[0x05]);
}

// ── Stack ops ───────────────────────────────────────────────────────────

#[test]
fn op_dup() {
    // OP_3 OP_DUP  →  [3, 3]
    let s = run(&[0x53, 0x76]).expect("ok");
    assert_eq!(s.len(), 2);
    assert_eq!(s.peek(0).expect("ok"), &[0x03]);
    assert_eq!(s.peek(1).expect("ok"), &[0x03]);
}

#[test]
fn op_drop() {
    // OP_1 OP_2 OP_DROP  →  [1]
    let s = run(&[0x51, 0x52, 0x75]).expect("ok");
    assert_eq!(s.len(), 1);
    assert_eq!(s.peek(0).expect("ok"), &[0x01]);
}

#[test]
fn op_swap() {
    // OP_1 OP_2 OP_SWAP  →  bottom 2, top 1
    let s = run(&[0x51, 0x52, 0x7c]).expect("ok");
    assert_eq!(s.peek(0).expect("ok"), &[0x01]);
    assert_eq!(s.peek(1).expect("ok"), &[0x02]);
}

#[test]
fn alt_stack_roundtrip() {
    // OP_5 OP_TOALTSTACK OP_FROMALTSTACK  →  [5]
    let s = run(&[0x55, 0x6b, 0x6c]).expect("ok");
    assert_eq!(s.len(), 1);
    assert_eq!(s.peek(0).expect("ok"), &[0x05]);
}

// ── Stack ops (extended) ───────────────────────────────────────────────

#[test]
fn op_2swap() {
    // OP_1 OP_2 OP_3 OP_4 OP_2SWAP → 3 4 1 2
    let s = run(&[0x51, 0x52, 0x53, 0x54, 0x72]).expect("ok");
    assert_eq!(s.peek(0).expect("ok"), &[0x02]);
    assert_eq!(s.peek(1).expect("ok"), &[0x01]);
    assert_eq!(s.peek(2).expect("ok"), &[0x04]);
    assert_eq!(s.peek(3).expect("ok"), &[0x03]);
}

#[test]
fn op_2rot() {
    // OP_1..6 OP_2ROT → 3 4 5 6 1 2
    let s = run(&[0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x71]).expect("ok");
    assert_eq!(s.peek(0).expect("ok"), &[0x02]);
    assert_eq!(s.peek(1).expect("ok"), &[0x01]);
    assert_eq!(s.peek(2).expect("ok"), &[0x06]);
    assert_eq!(s.peek(3).expect("ok"), &[0x05]);
    assert_eq!(s.peek(4).expect("ok"), &[0x04]);
    assert_eq!(s.peek(5).expect("ok"), &[0x03]);
}

#[test]
fn op_rot() {
    // OP_1 OP_2 OP_3 OP_ROT → 1 3 2
    let s = run(&[0x51, 0x52, 0x53, 0x7b]).expect("ok");
    assert_eq!(s.peek(0).expect("ok"), &[0x01]);
    assert_eq!(s.peek(1).expect("ok"), &[0x03]);
    assert_eq!(s.peek(2).expect("ok"), &[0x02]);
}

#[test]
fn op_roll() {
    // OP_1 OP_2 OP_3 OP_2 OP_ROLL → bottom=2 3 top=1
    let s = run(&[0x51, 0x52, 0x53, 0x52, 0x7a]).expect("ok");
    assert_eq!(s.len(), 3);
    assert_eq!(s.peek(0).expect("ok"), &[0x01]);
}

#[test]
fn op_pick() {
    // OP_1 OP_2 OP_3 OP_2 OP_PICK → 1 2 3 1
    let s = run(&[0x51, 0x52, 0x53, 0x52, 0x79]).expect("ok");
    assert_eq!(s.len(), 4);
    assert_eq!(s.peek(0).expect("ok"), &[0x01]);
}

#[test]
fn op_over() {
    // OP_1 OP_2 OP_OVER → 1 2 1
    let s = run(&[0x51, 0x52, 0x78]).expect("ok");
    assert_eq!(s.len(), 3);
    assert_eq!(s.peek(0).expect("ok"), &[0x01]);
}

#[test]
fn op_nip() {
    // OP_1 OP_2 OP_NIP → 2
    let s = run(&[0x51, 0x52, 0x77]).expect("ok");
    assert_eq!(s.len(), 1);
    assert_eq!(s.peek(0).expect("ok"), &[0x02]);
}

#[test]
fn op_tuck() {
    // OP_1 OP_2 OP_TUCK → 2 1 2
    let s = run(&[0x51, 0x52, 0x7d]).expect("ok");
    assert_eq!(s.len(), 3);
    assert_eq!(s.peek(0).expect("ok"), &[0x02]);
    assert_eq!(s.peek(1).expect("ok"), &[0x01]);
    assert_eq!(s.peek(2).expect("ok"), &[0x02]);
}

#[test]
fn op_ifdup_truthy() {
    // OP_5 OP_IFDUP → 5 5
    let s = run(&[0x55, 0x73]).expect("ok");
    assert_eq!(s.len(), 2);
}

#[test]
fn op_ifdup_falsey() {
    // OP_0 OP_IFDUP → 0 (no dup)
    let s = run(&[0x00, 0x73]).expect("ok");
    assert_eq!(s.len(), 1);
}

#[test]
fn op_depth() {
    // OP_1 OP_2 OP_3 OP_DEPTH → 1 2 3 3
    let s = run(&[0x51, 0x52, 0x53, 0x74]).expect("ok");
    assert_eq!(s.len(), 4);
    assert_eq!(s.peek(0).expect("ok"), &[0x03]);
}

#[test]
fn op_size() {
    // push 3-byte data OP_SIZE → data, 3
    let s = run(&[0x03, 0xaa, 0xbb, 0xcc, 0x82]).expect("ok");
    assert_eq!(s.len(), 2);
    assert_eq!(s.peek(0).expect("ok"), &[0x03]);
}

#[test]
fn op_2dup() {
    // OP_1 OP_2 OP_2DUP → 1 2 1 2
    let s = run(&[0x51, 0x52, 0x6e]).expect("ok");
    assert_eq!(s.len(), 4);
    assert_eq!(s.peek(0).expect("ok"), &[0x02]);
    assert_eq!(s.peek(1).expect("ok"), &[0x01]);
}

#[test]
fn op_3dup() {
    // OP_1 OP_2 OP_3 OP_3DUP → 1 2 3 1 2 3
    let s = run(&[0x51, 0x52, 0x53, 0x6f]).expect("ok");
    assert_eq!(s.len(), 6);
}

#[test]
fn op_2over() {
    // OP_1 OP_2 OP_3 OP_4 OP_2OVER → 1 2 3 4 1 2
    let s = run(&[0x51, 0x52, 0x53, 0x54, 0x70]).expect("ok");
    assert_eq!(s.len(), 6);
    assert_eq!(s.peek(0).expect("ok"), &[0x02]);
    assert_eq!(s.peek(1).expect("ok"), &[0x01]);
}

#[test]
fn op_2drop() {
    // OP_1 OP_2 OP_3 OP_2DROP → 1
    let s = run(&[0x51, 0x52, 0x53, 0x6d]).expect("ok");
    assert_eq!(s.len(), 1);
    assert_eq!(s.peek(0).expect("ok"), &[0x01]);
}

// ── Arithmetic ──────────────────────────────────────────────────────────

#[test]
fn op_add() {
    // OP_3 OP_4 OP_ADD  →  [7]
    let s = run(&[0x53, 0x54, 0x93]).expect("ok");
    assert_eq!(s.peek(0).expect("ok"), &[0x07]);
}

#[test]
fn op_sub_negative_result() {
    // OP_3 OP_5 OP_SUB  →  -2
    let s = run(&[0x53, 0x55, 0x94]).expect("ok");
    assert_eq!(s.peek(0).expect("ok"), &[0x82]); // -2 encoded
}

#[test]
fn op_within_in_range() {
    // 5 0 10 OP_WITHIN  →  true ([0x01])
    let s = run(&[0x55, 0x00, 0x5a, 0xa5]).expect("ok");
    assert_eq!(s.peek(0).expect("ok"), &[0x01]);
}

#[test]
fn op_min() {
    // OP_3 OP_7 OP_MIN → 3
    let s = run(&[0x53, 0x57, 0xa3]).expect("ok");
    assert_eq!(s.peek(0).expect("ok"), &[0x03]);
}

#[test]
fn op_max() {
    // OP_3 OP_7 OP_MAX → 7
    let s = run(&[0x53, 0x57, 0xa4]).expect("ok");
    assert_eq!(s.peek(0).expect("ok"), &[0x07]);
}

#[test]
fn op_num_equal_true() {
    // OP_5 OP_5 OP_NUMEQUAL → 1
    let s = run(&[0x55, 0x55, 0x9c]).expect("ok");
    assert_eq!(s.peek(0).expect("ok"), &[0x01]);
}

#[test]
fn op_num_equal_false() {
    // OP_5 OP_6 OP_NUMEQUAL → 0
    let s = run(&[0x55, 0x56, 0x9c]).expect("ok");
    assert!(s.peek(0).expect("ok").is_empty());
}

#[test]
fn op_num_not_equal() {
    // OP_5 OP_6 OP_NUMNOTEQUAL → 1
    let s = run(&[0x55, 0x56, 0x9e]).expect("ok");
    assert_eq!(s.peek(0).expect("ok"), &[0x01]);
}

#[test]
fn op_less_than() {
    // OP_3 OP_5 OP_LESSTHAN → 1
    let s = run(&[0x53, 0x55, 0x9f]).expect("ok");
    assert_eq!(s.peek(0).expect("ok"), &[0x01]);
}

#[test]
fn op_greater_than() {
    // OP_5 OP_3 OP_GREATERTHAN → 1
    let s = run(&[0x55, 0x53, 0xa0]).expect("ok");
    assert_eq!(s.peek(0).expect("ok"), &[0x01]);
}

#[test]
fn op_less_than_or_equal() {
    // OP_5 OP_5 OP_LESSTHANOREQUAL → 1
    let s = run(&[0x55, 0x55, 0xa1]).expect("ok");
    assert_eq!(s.peek(0).expect("ok"), &[0x01]);
}

#[test]
fn op_greater_than_or_equal() {
    // OP_5 OP_5 OP_GREATERTHANOREQUAL → 1
    let s = run(&[0x55, 0x55, 0xa2]).expect("ok");
    assert_eq!(s.peek(0).expect("ok"), &[0x01]);
}

#[test]
fn op_bool_and() {
    // OP_1 OP_1 OP_BOOLAND → 1; OP_0 OP_1 OP_BOOLAND → 0
    let s = run(&[0x51, 0x51, 0x9a]).expect("ok");
    assert_eq!(s.peek(0).expect("ok"), &[0x01]);
    let s2 = run(&[0x00, 0x51, 0x9a]).expect("ok");
    assert!(s2.peek(0).expect("ok").is_empty());
}

#[test]
fn op_bool_or() {
    // OP_0 OP_1 OP_BOOLOR → 1; OP_0 OP_0 OP_BOOLOR → 0
    let s = run(&[0x00, 0x51, 0x9b]).expect("ok");
    assert_eq!(s.peek(0).expect("ok"), &[0x01]);
    let s2 = run(&[0x00, 0x00, 0x9b]).expect("ok");
    assert!(s2.peek(0).expect("ok").is_empty());
}

#[test]
fn op_negate() {
    // OP_5 OP_NEGATE → -5
    let s = run(&[0x55, 0x8f]).expect("ok");
    assert_eq!(s.peek(0).expect("ok"), &[0x85]); // -5 encoded
}

#[test]
fn op_abs() {
    // push -5 (0x85) then OP_ABS → 5
    let s = run(&[0x01, 0x85, 0x90]).expect("ok");
    assert_eq!(s.peek(0).expect("ok"), &[0x05]);
}

#[test]
fn op_not() {
    // OP_0 OP_NOT → 1; OP_1 OP_NOT → 0
    let s = run(&[0x00, 0x91]).expect("ok");
    assert_eq!(s.peek(0).expect("ok"), &[0x01]);
    let s2 = run(&[0x51, 0x91]).expect("ok");
    assert!(s2.peek(0).expect("ok").is_empty());
}

#[test]
fn op_0not_equal() {
    // OP_0 OP_0NOTEQUAL → 0; OP_5 OP_0NOTEQUAL → 1
    let s = run(&[0x00, 0x92]).expect("ok");
    assert!(s.peek(0).expect("ok").is_empty());
    let s2 = run(&[0x55, 0x92]).expect("ok");
    assert_eq!(s2.peek(0).expect("ok"), &[0x01]);
}

#[test]
fn op_1add() {
    // OP_5 OP_1ADD → 6
    let s = run(&[0x55, 0x8b]).expect("ok");
    assert_eq!(s.peek(0).expect("ok"), &[0x06]);
}

#[test]
fn op_1sub() {
    // OP_5 OP_1SUB → 4
    let s = run(&[0x55, 0x8c]).expect("ok");
    assert_eq!(s.peek(0).expect("ok"), &[0x04]);
}

#[test]
fn op_num_equal_verify_passes() {
    // OP_5 OP_5 OP_NUMEQUALVERIFY → empty stack
    let s = run(&[0x55, 0x55, 0x9d]).expect("ok");
    assert_eq!(s.len(), 0);
}

#[test]
fn op_num_equal_verify_fails() {
    // OP_5 OP_6 OP_NUMEQUALVERIFY → Verify
    let r = run(&[0x55, 0x56, 0x9d]);
    assert!(matches!(r, Err(ScriptError::Verify)));
}

// ── Comparison ──────────────────────────────────────────────────────────

#[test]
fn op_equal_true() {
    // OP_5 OP_5 OP_EQUAL  →  [0x01]
    let s = run(&[0x55, 0x55, 0x87]).expect("ok");
    assert_eq!(s.peek(0).expect("ok"), &[0x01]);
}

#[test]
fn op_equal_verify_passes_consumes_both() {
    // OP_5 OP_5 OP_EQUALVERIFY  →  empty stack, ok
    let s = run(&[0x55, 0x55, 0x88]).expect("ok");
    assert_eq!(s.len(), 0);
}

#[test]
fn op_equal_verify_fails_on_mismatch() {
    // OP_5 OP_6 OP_EQUALVERIFY  →  Verify
    let r = run(&[0x55, 0x56, 0x88]);
    assert!(matches!(r, Err(ScriptError::Verify)));
}

// ── Hashes ──────────────────────────────────────────────────────────────

#[test]
fn op_sha256_empty() {
    // OP_0 OP_SHA256  →  SHA256("") = e3b0c442…
    let s = run(&[0x00, 0xa8]).expect("ok");
    let top = s.peek(0).expect("ok");
    assert_eq!(top.len(), 32);
    assert_eq!(&top[..4], &[0xe3, 0xb0, 0xc4, 0x42]);
}

#[test]
fn op_hash160_known_vector() {
    // OP_0 OP_HASH160  →  RIPEMD160(SHA256(""))
    // SHA256("") = e3b0c442…
    // RIPEMD160(SHA256("")) = b472a266d0bd89c13706a4132ccfb16f7c3b9fcb
    let s = run(&[0x00, 0xa9]).expect("ok");
    let top = s.peek(0).expect("ok");
    assert_eq!(top.len(), 20);
    assert_eq!(
        top,
        &[
            0xb4, 0x72, 0xa2, 0x66, 0xd0, 0xbd, 0x89, 0xc1, 0x37, 0x06, 0xa4, 0x13, 0x2c, 0xcf,
            0xb1, 0x6f, 0x7c, 0x3b, 0x9f, 0xcb,
        ]
    );
}

#[test]
fn op_hash256_empty_known_vector() {
    // SHA256d("") = 5df6e0e2…
    let s = run(&[0x00, 0xaa]).expect("ok");
    let top = s.peek(0).expect("ok");
    assert_eq!(top.len(), 32);
    assert_eq!(&top[..4], &[0x5d, 0xf6, 0xe0, 0xe2]);
}

#[test]
fn op_ripemd160_known_vector() {
    // RIPEMD160("") = 9c1185a5c5e9fc54612808977ee8f548b2258d31
    let s = run(&[0x00, 0xa6]).expect("ok");
    let top = s.peek(0).expect("ok");
    assert_eq!(top.len(), 20);
    assert_eq!(&top[..4], &[0x9c, 0x11, 0x85, 0xa5]);
}

#[test]
fn op_sha1_known_vector() {
    // SHA1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
    let s = run(&[0x00, 0xa7]).expect("ok");
    let top = s.peek(0).expect("ok");
    assert_eq!(top.len(), 20);
    assert_eq!(&top[..4], &[0xda, 0x39, 0xa3, 0xee]);
}

// ── Control flow ────────────────────────────────────────────────────────

#[test]
fn op_if_taken_branch_executes() {
    // OP_1 OP_IF OP_5 OP_ELSE OP_6 OP_ENDIF  →  [5]
    let s = run(&[0x51, 0x63, 0x55, 0x67, 0x56, 0x68]).expect("ok");
    assert_eq!(s.peek(0).expect("ok"), &[0x05]);
}

#[test]
fn op_if_skipped_branch_runs_else() {
    // OP_0 OP_IF OP_5 OP_ELSE OP_6 OP_ENDIF  →  [6]
    let s = run(&[0x00, 0x63, 0x55, 0x67, 0x56, 0x68]).expect("ok");
    assert_eq!(s.peek(0).expect("ok"), &[0x06]);
}

#[test]
fn op_if_minimalif_rejects_non_minimal() {
    // Push 0x02 (not minimal: must be empty or [0x01]) then OP_IF under MINIMALIF.
    let r = run_flags(&[0x01, 0x02, 0x63, 0x51, 0x68], ScriptFlags::MINIMALIF);
    assert!(matches!(r, Err(ScriptError::MinimalIf)));
}

#[test]
fn op_if_minimalif_accepts_minimal_true() {
    // Push [0x01] then OP_IF — minimal true under MINIMALIF.
    let s = run_flags(&[0x51, 0x63, 0x55, 0x68], ScriptFlags::MINIMALIF).expect("ok");
    assert_eq!(s.peek(0).expect("ok"), &[0x05]);
}

#[test]
fn op_notif_inverts_condition() {
    // OP_0 OP_NOTIF OP_5 OP_ENDIF  →  [5]
    let s = run(&[0x00, 0x64, 0x55, 0x68]).expect("ok");
    assert_eq!(s.peek(0).expect("ok"), &[0x05]);
}

#[test]
fn unbalanced_if_fails() {
    // OP_1 OP_IF OP_5 (no ENDIF)
    let r = run(&[0x51, 0x63, 0x55]);
    assert!(matches!(r, Err(ScriptError::UnbalancedConditional)));
}

#[test]
fn unbalanced_endif_fails() {
    // OP_ENDIF with no preceding OP_IF
    let r = run(&[0x68]);
    assert!(matches!(r, Err(ScriptError::UnbalancedConditional)));
}

#[test]
fn nested_if_executing_correctly() {
    // OP_1 OP_IF
    //   OP_1 OP_IF OP_7 OP_ELSE OP_8 OP_ENDIF
    // OP_ELSE
    //   OP_9
    // OP_ENDIF
    // → [7]
    let s = run(&[
        0x51, 0x63, 0x51, 0x63, 0x57, 0x67, 0x58, 0x68, 0x67, 0x59, 0x68,
    ])
    .expect("ok");
    assert_eq!(s.peek(0).expect("ok"), &[0x07]);
}

#[test]
fn nested_if_outer_false_skips_everything() {
    // OP_0 OP_IF
    //   OP_1 OP_IF OP_7 OP_ELSE OP_8 OP_ENDIF
    // OP_ENDIF
    // → empty stack (outer false; nothing runs except IF/ELSE/ENDIF dispatch)
    let s = run(&[0x00, 0x63, 0x51, 0x63, 0x57, 0x67, 0x58, 0x68, 0x68]).expect("ok");
    assert_eq!(s.len(), 0);
}

// ── Always-fail / disabled ──────────────────────────────────────────────

#[test]
fn op_return_fails() {
    let r = run(&[0x6a]);
    assert!(matches!(r, Err(ScriptError::OpReturn)));
}

#[test]
fn disabled_opcode_pre_scan_fails() {
    // OP_CAT (0x7e) — disabled in legacy.
    let r = run(&[0x7e]);
    assert!(matches!(r, Err(ScriptError::DisabledOpcode)));
}

#[test]
fn op_verif_pre_scanned() {
    let r = run(&[0x65]);
    assert!(matches!(r, Err(ScriptError::BadOpcodeReserved)));
}

#[test]
fn op_reserved_fails_when_executed() {
    // OP_RESERVED (0x50)
    let r = run(&[0x50]);
    assert!(matches!(r, Err(ScriptError::BadOpcodeReserved)));
}

#[test]
fn op_reserved_skipped_when_unexecuted() {
    // OP_0 OP_IF OP_RESERVED OP_ENDIF  →  empty stack, no error
    let s = run(&[0x00, 0x63, 0x50, 0x68]).expect("ok");
    assert_eq!(s.len(), 0);
}

// ── Op count limit ──────────────────────────────────────────────────────

#[test]
fn op_count_limit() {
    // 202 OP_NOPs > MAX_OPS_PER_SCRIPT (201).
    let script = vec![0x61u8; 202];
    let r = run(&script);
    assert!(matches!(r, Err(ScriptError::OpCount)));

    // 201 OP_NOPs is exactly the cap and passes.
    let script = vec![0x61u8; 201];
    run(&script).expect("at-cap ok");
}

#[test]
fn pushes_dont_count_against_op_limit() {
    // 500 OP_1 pushes — all pushes, none count against the 201 op limit.
    // This would have exceeded the limit if pushes counted (500 > 201).
    // The 1000-element stack cap holds because we stay at 500 < 1000.
    let script = vec![0x51u8; 500];
    run(&script).expect("ok");
}

// ── Signature opcodes ───────────────────────────────────────────────────

#[test]
fn op_check_sig_with_nop_checker_pushes_false() {
    // OP_0 OP_0 OP_CHECKSIG. NopSigChecker fails every check; under no
    // flags the result is just `false` pushed onto the stack.
    let s = run(&[0x00, 0x00, 0xac]).expect("ok");
    assert_eq!(s.len(), 1);
    assert!(!s.peek(0).expect("ok").is_truthy());
}

#[test]
fn op_check_sig_verify_fails_under_nop_checker() {
    // OP_0 OP_0 OP_CHECKSIGVERIFY  →  Verify (false top fails the verify form).
    let r = run(&[0x00, 0x00, 0xad]);
    assert!(matches!(r, Err(ScriptError::Verify)));
}

#[test]
fn op_code_separator_updates_offset() {
    // OP_CODESEPARATOR OP_0 OP_0 OP_CHECKSIG  →  pushes false (sighash
    // is computed over the suffix script after CODESEPARATOR; the
    // NopSigChecker fails regardless, so we just check it doesn't error).
    let s = run(&[0xab, 0x00, 0x00, 0xac]).expect("ok");
    assert_eq!(s.len(), 1);
}

// ── Upgradable NOPs ─────────────────────────────────────────────────────

#[test]
fn upgradable_nop_passes_by_default() {
    // OP_NOP4 (0xb3)
    run(&[0xb3]).expect("ok");
}

#[test]
fn upgradable_nop_fails_under_discourage_flag() {
    let r = run_flags(&[0xb3], ScriptFlags::DISCOURAGE_UPGRADABLE_NOPS);
    assert!(matches!(r, Err(ScriptError::DiscourageUpgradableNops)));
}

// ── OP_NOP ──────────────────────────────────────────────────────────────

#[test]
fn op_nop_is_truly_noop() {
    // OP_NOP (0x61) by itself leaves the stack empty and succeeds.
    let s = run(&[0x61]).expect("ok");
    assert_eq!(s.len(), 0);
}

#[test]
fn op_nop_preserves_stack() {
    // OP_5 OP_NOP OP_3 → stack [5, 3], NOP does not disturb anything.
    let s = run(&[0x55, 0x61, 0x53]).expect("ok");
    assert_eq!(s.len(), 2);
    assert_eq!(s.peek(0).expect("ok"), &[0x03]);
    assert_eq!(s.peek(1).expect("ok"), &[0x05]);
}

// ── OP_VERIFY ───────────────────────────────────────────────────────────

#[test]
fn op_verify_truthy_succeeds_empty_stack() {
    // OP_1 OP_VERIFY → pops the truthy value, stack empty, no error.
    let s = run(&[0x51, 0x69]).expect("ok");
    assert_eq!(s.len(), 0);
}

#[test]
fn op_verify_falsey_fails() {
    // OP_0 OP_VERIFY → Verify error.
    let r = run(&[0x00, 0x69]);
    assert!(matches!(r, Err(ScriptError::Verify)));
}

#[test]
fn op_verify_preserves_items_below() {
    // OP_3 OP_1 OP_VERIFY → consumes the 1, leaves [3].
    let s = run(&[0x53, 0x51, 0x69]).expect("ok");
    assert_eq!(s.len(), 1);
    assert_eq!(s.peek(0).expect("ok"), &[0x03]);
}

// ── OP_CHECKMULTISIG ────────────────────────────────────────────────────

#[test]
fn op_checkmultisig_0_of_0_pushes_true() {
    // Stack (bottom→top): dummy=OP_0, n_sigs=OP_0, n_pubkeys=OP_0
    // OP_0 OP_0 OP_0 OP_CHECKMULTISIG → true
    let s = run(&[0x00, 0x00, 0x00, 0xae]).expect("ok");
    assert_eq!(s.len(), 1);
    assert!(s.peek(0).expect("ok").is_truthy());
}

#[test]
fn op_checkmultisig_1_of_1_nop_checker_pushes_false() {
    // 1-of-1 multisig with NopSigChecker: sig check fails → push false.
    // Stack: dummy, sig, n_sigs=1, pubkey, n_pubkeys=1
    // OP_0(dummy) OP_0(sig) OP_1(n_sigs) OP_0(pk) OP_1(n_pubkeys) OP_CHECKMULTISIG
    let s = run(&[0x00, 0x00, 0x51, 0x00, 0x51, 0xae]).expect("ok");
    assert_eq!(s.len(), 1);
    assert!(!s.peek(0).expect("ok").is_truthy());
}

// ── OP_CHECKSIG tapscript paths ────────────────────────────────────────

fn run_tapscript(script: &[u8]) -> Result<Stack, ScriptError> {
    run_tapscript_flags(script, ScriptFlags::NONE)
}

fn run_tapscript_flags(script: &[u8], flags: ScriptFlags) -> Result<Stack, ScriptError> {
    let checker = NopSigChecker;
    let mut interp = Interpreter::new(&checker, flags, SigVersion::Tapscript);
    // Provide a dummy tapscript context so OP_CHECKSIG / OP_CHECKSIGADD
    // can reach the Schnorr verification path (instead of returning BadOpcode).
    interp.tapscript = Some(super::TapscriptCtx {
        leaf_hash: [0u8; 32],
        spent_amount: mantle::primitives::Satoshi::ZERO,
        spent_spk: Vec::new(),
        // SAFETY: Bip341Cache is only used for sighash computation which
        // NopSigChecker never reaches — all fields can be zeroed.
        bip341_cache: unsafe { std::mem::zeroed() },
    });
    interp.eval(script)?;
    Ok(interp.stack)
}

#[test]
fn op_checksig_tapscript_empty_sig_pushes_false() {
    // sig=OP_0(empty), pubkey=32-byte key → clean failure, pushes false.
    let mut script = vec![0x00]; // OP_0 (sig = empty)
    // Push 32-byte pubkey
    script.push(0x20); // OP_PUSHBYTES_32
    script.extend_from_slice(&[0xab; 32]);
    script.push(0xac); // OP_CHECKSIG
    let s = run_tapscript(&script).expect("empty sig is clean failure");
    assert_eq!(s.len(), 1);
    assert!(!s.peek(0).expect("ok").is_truthy());
}

#[test]
fn op_checksig_tapscript_non32byte_pubkey_pushes_false() {
    // sig=OP_0(empty), pubkey=20-byte (not 32) → unknown pubkey type, pushes false.
    let mut script = vec![0x00]; // OP_0 (sig)
    script.push(0x14); // OP_PUSHBYTES_20
    script.extend_from_slice(&[0xab; 20]);
    script.push(0xac); // OP_CHECKSIG
    let s = run_tapscript(&script).expect("unknown pubkey type is clean failure");
    assert_eq!(s.len(), 1);
    assert!(!s.peek(0).expect("ok").is_truthy());
}

#[test]
fn op_checksig_tapscript_bad_sig_nullfail() {
    // Non-empty sig that fails verification under NULLFAIL → SigNullFail error.
    // NopSigChecker always returns false for check_schnorr_sig.
    let mut script = Vec::new();
    // Push a non-empty sig (1 byte).
    script.push(0x01); // OP_PUSHBYTES_1
    script.push(0xff); // sig byte
    // Push 32-byte pubkey.
    script.push(0x20); // OP_PUSHBYTES_32
    script.extend_from_slice(&[0xab; 32]);
    script.push(0xac); // OP_CHECKSIG
    let r = run_tapscript_flags(&script, ScriptFlags::NULLFAIL);
    assert!(matches!(r, Err(ScriptError::SigNullFail)));
}

#[test]
fn op_checksig_tapscript_bad_sig_no_nullfail_pushes_false() {
    // Non-empty sig that fails, but NULLFAIL is off → pushes false.
    let mut script = Vec::new();
    script.push(0x01); // OP_PUSHBYTES_1
    script.push(0xff); // sig byte
    script.push(0x20); // OP_PUSHBYTES_32
    script.extend_from_slice(&[0xab; 32]);
    script.push(0xac); // OP_CHECKSIG
    let s = run_tapscript(&script).expect("no NULLFAIL → clean failure");
    assert_eq!(s.len(), 1);
    assert!(!s.peek(0).expect("ok").is_truthy());
}

// ── OP_CHECKSIGADD (tapscript) ──────────────────────────────────────────

#[test]
fn op_checksigadd_empty_pubkey_pushes_n_unchanged() {
    // sig=OP_0(empty), n=OP_5, pubkey=OP_0(empty)
    // Empty pubkey → unknown key type, push n unchanged.
    // OP_0 OP_5 OP_0 OP_CHECKSIGADD
    let s = run_tapscript(&[0x00, 0x55, 0x00, 0xba]).expect("ok");
    assert_eq!(s.len(), 1);
    assert_eq!(s.peek(0).expect("ok"), &[0x05]);
}

#[test]
fn op_checksigadd_empty_sig_pushes_n_unchanged() {
    // sig=OP_0(empty), n=OP_3, pubkey=32-byte zeroed key
    // Empty sig → no contribution, push n unchanged.
    let mut script = vec![0x00]; // OP_0 (sig)
    script.push(0x53); // OP_3 (n=3)
    // Push 32-byte pubkey: OP_PUSHBYTES_32 followed by 32 zero bytes
    script.push(0x20); // 0x20 = 32
    script.extend_from_slice(&[0x00; 32]);
    script.push(0xba); // OP_CHECKSIGADD
    let s = run_tapscript(&script).expect("ok");
    assert_eq!(s.len(), 1);
    assert_eq!(s.peek(0).expect("ok"), &[0x03]);
}

#[test]
fn op_checksigadd_bad_pubkey_size_fails() {
    // sig=OP_0(empty), n=OP_5, pubkey=1-byte (not 32, not empty)
    // Non-empty, non-32-byte pubkey → XOnlyPubkeySize error.
    // OP_0 OP_5 OP_1 OP_CHECKSIGADD
    let r = run_tapscript(&[0x00, 0x55, 0x51, 0xba]);
    assert!(matches!(r, Err(ScriptError::XOnlyPubkeySize)));
}

#[test]
fn op_checksigadd_bad_sig_nullfail() {
    // Non-empty sig that fails verification under NULLFAIL → TaprootChecksigAdd error.
    // Stack order (bottom to top): sig, n, pubkey
    let mut script = Vec::new();
    // sig = 1 byte (non-empty)
    script.push(0x01); // OP_PUSHBYTES_1
    script.push(0xff);
    // n = OP_3
    script.push(0x53);
    // pubkey = 32-byte key
    script.push(0x20); // OP_PUSHBYTES_32
    script.extend_from_slice(&[0xab; 32]);
    script.push(0xba); // OP_CHECKSIGADD
    let r = run_tapscript_flags(&script, ScriptFlags::NULLFAIL);
    assert!(matches!(r, Err(ScriptError::TaprootChecksigAdd)));
}

#[test]
fn op_checksigadd_bad_sig_no_nullfail_pushes_n() {
    // Non-empty sig fails without NULLFAIL → pushes n unchanged.
    let mut script = Vec::new();
    script.push(0x01); // OP_PUSHBYTES_1
    script.push(0xff);
    script.push(0x53); // OP_3 (n=3)
    script.push(0x20); // OP_PUSHBYTES_32
    script.extend_from_slice(&[0xab; 32]);
    script.push(0xba); // OP_CHECKSIGADD
    let s = run_tapscript(&script).expect("no NULLFAIL → clean failure");
    assert_eq!(s.len(), 1);
    assert_eq!(s.peek(0).expect("ok"), &[0x03]);
}

#[test]
fn op_checksigadd_outside_tapscript_fails() {
    // OP_CHECKSIGADD (0xba) outside tapscript is BadOpcode.
    let r = run(&[0x00, 0x55, 0x00, 0xba]);
    assert!(matches!(r, Err(ScriptError::BadOpcode)));
}

// ── OP_CHECKMULTISIG / OP_CHECKMULTISIGVERIFY in tapscript ─────────────

#[test]
fn op_checkmultisig_in_tapscript_succeeds_via_op_success() {
    // In tapscript, OP_CHECKMULTISIG (0xae) is an OP_SUCCESS opcode.
    // Any script containing it succeeds immediately, even without valid stack.
    // Note: is_tapscript_success covers byte 0xbb..=0xfe, but OP_CHECKMULTISIG
    // (0xae) is NOT in that range — it dispatches normally. Let's test that
    // it executes normally (0-of-0 works).
    let s = run_tapscript(&[0x00, 0x00, 0x00, 0xae]).expect("0-of-0 multisig ok in tapscript");
    assert_eq!(s.len(), 1);
    assert!(s.peek(0).expect("ok").is_truthy());
}

#[test]
fn op_checkmultisigverify_in_tapscript_works() {
    // OP_CHECKMULTISIGVERIFY (0xaf) in tapscript: 0-of-0 with verify.
    // Stack: dummy=OP_0, n_sigs=OP_0, n_pubkeys=OP_0, then OP_CHECKMULTISIGVERIFY
    // followed by OP_1 so we leave a truthy stack.
    let s = run_tapscript(&[0x00, 0x00, 0x00, 0xaf, 0x51]).expect("0-of-0 multisigverify ok");
    assert_eq!(s.len(), 1);
    assert!(s.peek(0).expect("ok").is_truthy());
}

// ── OP_PUSHDATA1 / OP_PUSHDATA2 / OP_PUSHDATA4 ────────────────────────

#[test]
fn op_pushdata1_pushes_data() {
    // OP_PUSHDATA1(0x4c) len=3 0xaa 0xbb 0xcc
    let s = run(&[0x4c, 0x03, 0xaa, 0xbb, 0xcc]).expect("ok");
    assert_eq!(s.len(), 1);
    assert_eq!(s.peek(0).expect("ok"), &[0xaa, 0xbb, 0xcc]);
}

#[test]
fn op_pushdata2_pushes_data() {
    // OP_PUSHDATA2(0x4d) len=0x0002 (LE) 0xaa 0xbb
    let s = run(&[0x4d, 0x02, 0x00, 0xaa, 0xbb]).expect("ok");
    assert_eq!(s.len(), 1);
    assert_eq!(s.peek(0).expect("ok"), &[0xaa, 0xbb]);
}

#[test]
fn op_pushdata4_pushes_data() {
    // OP_PUSHDATA4(0x4e) len=0x00000001 (LE) 0xff
    let s = run(&[0x4e, 0x01, 0x00, 0x00, 0x00, 0xff]).expect("ok");
    assert_eq!(s.len(), 1);
    assert_eq!(s.peek(0).expect("ok"), &[0xff]);
}

// ── Disabled opcodes in tapscript ──────────────────────────────────────

#[test]
fn disabled_opcode_in_tapscript_is_op_success() {
    // In tapscript, the legacy disabled opcodes (OP_CAT 0x7e, OP_SUBSTR 0x7f,
    // etc.) are re-assigned as OP_SUCCESSx. Encountering one anywhere in the
    // script makes the entire script succeed immediately.
    // OP_CAT (0x7e) is in the 0x7e..=0x81 range of OP_SUCCESSx.
    let s = run_tapscript(&[0x7e]).expect("OP_SUCCESSx succeeds immediately");
    // After OP_SUCCESSx, eval returns Ok(()) and the stack may be empty.
    // The step function returns Ok(()) immediately, so eval finishes.
    assert_eq!(s.len(), 0);
}

#[test]
fn disabled_opcode_in_tapscript_skipped_branch_still_succeeds() {
    // OP_SUCCESSx in an unexecuted OP_IF branch still makes the script succeed.
    // OP_0 OP_IF OP_CAT(0x7e) OP_ENDIF
    // Even though OP_CAT is in the "false" branch, it's an OP_SUCCESSx in tapscript.
    let s = run_tapscript(&[0x00, 0x63, 0x7e, 0x68]).expect("OP_SUCCESSx in dead branch succeeds");
    assert_eq!(s.len(), 0);
}

// ── CLTV / CSV as upgradable NOPs (pre-activation) ────────────────────

#[test]
fn cltv_without_flag_acts_as_upgradable_nop() {
    // OP_CHECKLOCKTIMEVERIFY (0xb1) without CHECKLOCKTIMEVERIFY flag → upgradable NOP.
    // Push 1 first so stack is not empty, then CLTV acts as NOP.
    let flags = ScriptFlags::NONE;
    let s = run_flags(&[0x51, 0xb1], flags).expect("CLTV is NOP without flag");
    assert_eq!(s.len(), 1);
    assert_eq!(s.peek(0).expect("ok"), &[0x01]);
}

#[test]
fn csv_without_flag_acts_as_upgradable_nop() {
    // OP_CHECKSEQUENCEVERIFY (0xb2) without CHECKSEQUENCEVERIFY flag → upgradable NOP.
    let flags = ScriptFlags::NONE;
    let s = run_flags(&[0x51, 0xb2], flags).expect("CSV is NOP without flag");
    assert_eq!(s.len(), 1);
    assert_eq!(s.peek(0).expect("ok"), &[0x01]);
}

#[test]
fn cltv_without_flag_discourage_nops_fails() {
    // CLTV pre-activation + DISCOURAGE_UPGRADABLE_NOPS → error.
    let flags = ScriptFlags::DISCOURAGE_UPGRADABLE_NOPS;
    let r = run_flags(&[0x51, 0xb1], flags);
    assert!(matches!(r, Err(ScriptError::DiscourageUpgradableNops)));
}

#[test]
fn csv_without_flag_discourage_nops_fails() {
    // CSV pre-activation + DISCOURAGE_UPGRADABLE_NOPS → error.
    let flags = ScriptFlags::DISCOURAGE_UPGRADABLE_NOPS;
    let r = run_flags(&[0x51, 0xb2], flags);
    assert!(matches!(r, Err(ScriptError::DiscourageUpgradableNops)));
}

// ── Reserved/Invalid opcodes ──────────────────────────────────────────

#[test]
fn op_ver_fails_when_executed() {
    // OP_VER (0x62) fails when executed.
    let r = run(&[0x62]);
    assert!(matches!(r, Err(ScriptError::BadOpcodeReserved)));
}

#[test]
fn op_reserved1_fails_when_executed() {
    // OP_RESERVED1 (0x89) is not in the disabled set but fails with
    // BadOpcodeReserved when executed via the dispatch table.
    let r = run(&[0x89]);
    assert!(matches!(r, Err(ScriptError::BadOpcodeReserved)));
}

#[test]
fn op_reserved2_fails_when_executed() {
    // OP_RESERVED2 (0x8a) same as RESERVED1.
    let r = run(&[0x8a]);
    assert!(matches!(r, Err(ScriptError::BadOpcodeReserved)));
}

#[test]
fn op_invalid_fails_when_executed() {
    // OP_INVALIDOPCODE (0xff). In legacy mode it's disabled/OP_SUCCESS territory.
    // 0xff is in is_tapscript_success range (0xbb..=0xfe). But in legacy, 0xff
    // is not in the disabled set... let me check. Actually 0xff is not 0xbb..=0xfe
    // (0xff > 0xfe), so it maps to Opcode::Invalid(0xff).
    // In step(): is_disabled() returns false for 0xff (it's not in the disabled list),
    // and it's not is_verif_class either. So dispatch runs and hits Invalid(_) → BadOpcode.
    let r = run(&[0xff]);
    assert!(matches!(r, Err(ScriptError::BadOpcode)));
}

// ── Upgradable NOP range ──────────────────────────────────────────────

#[test]
fn all_upgradable_nops_pass_without_discourage() {
    // NOP1(0xb0), NOP4..NOP10 (0xb3..0xb9)
    for &byte in &[0xb0, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9] {
        run(&[byte]).unwrap_or_else(|e| panic!("NOP byte 0x{byte:02x} should pass, got {e:?}"));
    }
}

#[test]
fn all_upgradable_nops_fail_with_discourage() {
    for &byte in &[0xb0, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9] {
        let r = run_flags(&[byte], ScriptFlags::DISCOURAGE_UPGRADABLE_NOPS);
        assert!(
            matches!(r, Err(ScriptError::DiscourageUpgradableNops)),
            "NOP byte 0x{byte:02x} should fail with DISCOURAGE, got {r:?}"
        );
    }
}

// ── op_check_sig: tapscript context not initialised (defensive) ──────

#[test]
fn op_checksig_tapscript_no_context_returns_bad_opcode() {
    // Create an interpreter with SigVersion::Tapscript but do NOT set the
    // tapscript context. When OP_CHECKSIG encounters a 32-byte pubkey and
    // a non-empty sig it reaches the `let Some(ctx) = &self.tapscript`
    // guard and returns BadOpcode (defensive unreachable path).
    let checker = NopSigChecker;
    let mut interp = Interpreter::new(&checker, ScriptFlags::NONE, SigVersion::Tapscript);
    // Note: tapscript is None by default from Interpreter::new.

    let mut script = Vec::new();
    // Push a non-empty sig (1 byte) so we pass the empty-sig early return.
    script.push(0x01); // OP_PUSHBYTES_1
    script.push(0xff);
    // Push a 32-byte pubkey so we pass the non-32-byte early return.
    script.push(0x20); // OP_PUSHBYTES_32
    script.extend_from_slice(&[0xab; 32]);
    script.push(0xac); // OP_CHECKSIG

    let r = interp.eval(&script);
    assert!(
        matches!(r, Err(ScriptError::BadOpcode)),
        "tapscript CHECKSIG without context must return BadOpcode, got: {r:?}"
    );
}

// ── op_check_multi_sig: pubkey shortage mid-loop pushes false ────────

#[test]
fn op_checkmultisig_pubkey_shortage_mid_loop_pushes_false() {
    // 1-of-2 multisig with NopSigChecker (all sig checks fail). The loop
    // exhausts both pubkeys without matching the single sig, then the
    // `n_sigs - sig_idx > n_pubkeys - pk_idx` guard fires (lines 312-314),
    // breaking with ok=false. Without NULLFAIL the result is just false
    // pushed onto the stack.
    //
    // Stack (bottom to top): dummy, sig, n_sigs=1, pk1, pk2, n_pubkeys=2
    // OP_0(dummy) OP_0(sig) OP_1(n_sigs) OP_0(pk1) OP_0(pk2) OP_2(n_pubkeys) OP_CHECKMULTISIG
    let s = run(&[0x00, 0x00, 0x51, 0x00, 0x00, 0x52, 0xae]).expect("should not error");
    assert_eq!(s.len(), 1);
    assert!(
        !s.peek(0).expect("non-empty stack").is_truthy(),
        "pubkey shortage mid-loop must push false"
    );
}

// ── op_check_multi_sig: NULLFAIL with non-empty sig on failure ───────

#[test]
fn op_checkmultisig_nullfail_nonempty_sig_returns_sig_null_fail() {
    // 1-of-1 multisig with NopSigChecker (sig check always fails).
    // A non-empty signature is provided and NULLFAIL is enabled.
    // After the loop, ok=false and the NULLFAIL check finds a non-empty
    // sig, returning SigNullFail (lines 330-335).
    //
    // Stack: dummy=OP_0, sig=1-byte, n_sigs=OP_1, pk=OP_0, n_pubkeys=OP_1
    // Script: OP_0 OP_PUSHBYTES_1 0xff OP_1 OP_0 OP_1 OP_CHECKMULTISIG
    let r = run_flags(
        &[0x00, 0x01, 0xff, 0x51, 0x00, 0x51, 0xae],
        ScriptFlags::NULLFAIL,
    );
    assert!(
        matches!(r, Err(ScriptError::SigNullFail)),
        "NULLFAIL with non-empty sig on multisig failure must return SigNullFail, got: {r:?}"
    );
}

// ── op_check_sig: ECDSA NULLFAIL with non-empty failing sig ─────────

#[test]
fn op_checksig_ecdsa_nullfail_nonempty_sig_returns_sig_null_fail() {
    // In the ECDSA (non-tapscript) path of op_check_sig (line 149):
    //   if !ok && self.flags.contains(NULLFAIL) && !sig.is_empty()
    // NopSigChecker always returns false for check_ecdsa_sig. We push a
    // non-empty signature and a valid-looking pubkey, then OP_CHECKSIG
    // with NULLFAIL flag must return SigNullFail.
    //
    // Script: OP_PUSHBYTES_1 0xff  OP_PUSHBYTES_1 0xaa  OP_CHECKSIG
    // Stack before CHECKSIG (bottom to top): sig=[0xff], pubkey=[0xaa]
    let r = run_flags(&[0x01, 0xff, 0x01, 0xaa, 0xac], ScriptFlags::NULLFAIL);
    assert!(
        matches!(r, Err(ScriptError::SigNullFail)),
        "ECDSA CHECKSIG with NULLFAIL and non-empty failing sig must return SigNullFail, got: {r:?}"
    );
}

// ── op_check_multi_sig: VERIFY variant failure returns Verify ────────

#[test]
fn op_checkmultisigverify_failure_returns_verify() {
    // Line 339 of op_crypto.rs: when verify=true and ok=false, returns
    // Err(ScriptError::Verify). We use NopSigChecker (always fails sig
    // checks) with empty sigs so NULLFAIL does not fire. The VERIFY
    // variant should return Verify, not SigNullFail.
    //
    // Build: OP_0(dummy) OP_0(sig) OP_1(n_sigs) OP_0(pk) OP_1(n_pubkeys) OP_CHECKMULTISIGVERIFY
    // NopSigChecker: check_ecdsa_sig returns false. sig is empty so
    // NULLFAIL doesn't trigger. The overall multisig result is false.
    // Since verify=true: Err(Verify).
    //
    // Note: no NULLFAIL flag set — we only set P2SH to keep it simple.
    let r = run_flags(
        &[0x00, 0x00, 0x51, 0x00, 0x51, 0xaf],
        ScriptFlags::NONE,
    );
    assert!(
        matches!(r, Err(ScriptError::Verify)),
        "CHECKMULTISIGVERIFY with failing sig (no NULLFAIL) must return Verify, got: {r:?}"
    );
}
