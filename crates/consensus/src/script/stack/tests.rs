use super::*;

/// All tests use the default 32-byte inline cap.
type TestStack = Stack<DEFAULT_INLINE_CAP>;

#[test]
fn empty_pop_is_invalid_stack_op() {
    let mut s = TestStack::new();
    assert!(matches!(s.pop(), Err(ScriptError::InvalidStackOperation)));
}

#[test]
fn push_then_peek_then_pop() {
    let mut s = TestStack::new();
    s.push_checked(&[1, 2, 3], 0).expect("under both caps");
    s.push_checked(&[4, 5], 0).expect("under both caps");
    assert_eq!(s.len(), 2);
    assert_eq!(s.peek(0).expect("non-empty"), &[4, 5]);
    assert_eq!(s.peek(1).expect("non-empty"), &[1, 2, 3]);
    assert_eq!(s.pop().expect("non-empty").as_slice(), &[4, 5]);
    assert_eq!(s.pop().expect("non-empty").as_slice(), &[1, 2, 3]);
    assert!(s.is_empty());
}

#[test]
fn peek_past_bottom_is_invalid_stack_op() {
    let mut s = TestStack::new();
    s.push_checked(&[1], 0).expect("ok");
    assert!(matches!(s.peek(1), Err(ScriptError::InvalidStackOperation)));
}

#[test]
fn push_size_cap() {
    let mut s = TestStack::new();
    let oversized = vec![0u8; MAX_SCRIPT_ELEMENT_SIZE + 1];
    assert!(matches!(
        s.push_checked(&oversized, 0),
        Err(ScriptError::PushSize)
    ));
    let max = vec![0u8; MAX_SCRIPT_ELEMENT_SIZE];
    assert!(s.push_checked(&max, 0).is_ok());
}

#[test]
fn combined_stack_size_cap() {
    let mut s = TestStack::new();
    // Fill the main stack to just under the cap.
    for _ in 0..MAX_STACK_SIZE - 1 {
        s.push_checked(&[], 0).expect("under cap");
    }
    // One more push reaches the cap (combined depth = 1000); the next fails.
    s.push_checked(&[], 0).expect("at cap is fine");
    assert!(matches!(
        s.push_checked(&[], 0),
        Err(ScriptError::StackSize)
    ));
}

#[test]
fn combined_cap_uses_altstack_len() {
    let mut s = TestStack::new();
    // Pretend the alt stack has 999 items already.
    s.push_checked(&[], 999)
        .expect("combined = 999 + 1 <= 1000");
    assert!(matches!(
        s.push_checked(&[], 999),
        Err(ScriptError::StackSize)
    ));
}

#[test]
fn remove_at_shifts() {
    let mut s = TestStack::new();
    for i in 0u8..3 {
        s.push_checked(&[i], 0).expect("ok");
    }
    // Stack from bottom to top: [0], [1], [2]. Top is depth 0.
    let removed = s.remove_at(1).expect("depth 1 exists");
    assert_eq!(removed.as_slice(), &[1]);
    assert_eq!(s.peek(0).expect("non-empty"), &[2]);
    assert_eq!(s.peek(1).expect("non-empty"), &[0]);
}

#[test]
fn truncate_to_smaller() {
    let mut s = TestStack::new();
    for i in 0u8..5 {
        s.push_checked(&[i], 0).expect("ok");
    }
    s.truncate(2).expect("smaller");
    assert_eq!(s.len(), 2);
    assert!(matches!(
        s.truncate(99),
        Err(ScriptError::InvalidStackOperation)
    ));
}

#[test]
fn dup_at_avoids_double_alloc() {
    let mut s = TestStack::new();
    s.push_checked(&[0xab; 20], 0).expect("ok");
    s.dup_at(0, 0).expect("ok");
    assert_eq!(s.len(), 2);
    assert_eq!(s.peek(0).expect("non-empty"), &[0xab; 20]);
    assert_eq!(s.peek(1).expect("non-empty"), &[0xab; 20]);
}

// ── Inline vs heap ──────────────────────────────────────────────────────

#[test]
fn small_value_stays_inline() {
    let elem = StackElement::<32>::from_slice(&[1, 2, 3]);
    assert!(matches!(elem, StackElement::Inline { .. }));
    assert_eq!(elem.as_slice(), &[1, 2, 3]);
}

#[test]
fn at_inline_cap_stays_inline() {
    let elem = StackElement::<32>::from_slice(&[0xab; 32]);
    assert!(matches!(elem, StackElement::Inline { .. }));
    assert_eq!(elem.len(), 32);
}

#[test]
fn over_inline_cap_goes_heap() {
    let elem = StackElement::<32>::from_slice(&[0xcd; 33]);
    assert!(matches!(elem, StackElement::Heap(_)));
    assert_eq!(elem.len(), 33);
    assert_eq!(elem.as_slice(), &[0xcd; 33]);
}

#[test]
fn empty_constant() {
    let elem: StackElement<32> = StackElement::EMPTY;
    assert!(elem.is_empty());
    assert!(matches!(elem, StackElement::Inline { len: 0, .. }));
}

// ── High-level helpers ──────────────────────────────────────────────────

#[test]
fn push_pop_num_roundtrip() {
    let mut s = TestStack::new();
    for v in [-127, -1, 0, 1, 127, 128, 0x7fff_ffff] {
        s.push_num(v, 0).expect("ok");
        assert_eq!(s.pop_num(4, false).expect("ok"), v);
    }
}

#[test]
fn pop_num_respects_size_limit() {
    let mut s = TestStack::new();
    // Five-byte encoding pushed.
    s.push_num(0x007f_ffff_ffff_i64, 0).expect("ok");
    // Arithmetic limit (4) rejects it.
    assert!(matches!(s.pop_num(4, false), Err(ScriptError::NumOverflow)));
}

#[test]
fn pop_num_minimal_check() {
    let mut s = TestStack::new();
    // Non-minimal encoding of zero.
    s.push_unchecked(StackElement::from_slice(&[0x00]));
    assert!(matches!(
        s.pop_num(4, true),
        Err(ScriptError::NumNotMinimal)
    ));
}

#[test]
fn is_truthy_rules() {
    let t = |b: &[u8]| StackElement::<32>::from_slice(b).is_truthy();
    // Empty is false.
    assert!(!t(&[]));
    // All-zero bytes is false.
    assert!(!t(&[0, 0, 0]));
    // Single 0x80 (negative zero) is false.
    assert!(!t(&[0x80]));
    // 0x00 0x80 is also false (mantissa zero, sign byte only).
    assert!(!t(&[0x00, 0x80]));
    // Any non-zero byte before the last makes it true.
    assert!(t(&[0x01, 0x80]));
    // A non-sign-only last byte is true.
    assert!(t(&[0x01]));
    assert!(t(&[0x7f]));
}

#[test]
fn push_pop_bool() {
    let mut s = TestStack::new();
    s.push_bool(true, 0).expect("ok");
    s.push_bool(false, 0).expect("ok");
    assert!(!s.pop_bool().expect("ok"));
    assert!(s.pop_bool().expect("ok"));
}

#[test]
fn push_bool_encodes_canonically() {
    let mut s = TestStack::new();
    s.push_bool(true, 0).expect("ok");
    assert_eq!(s.peek(0).expect("non-empty"), &[0x01]);
    s.pop().expect("ok");
    s.push_bool(false, 0).expect("ok");
    assert!(s.peek(0).expect("non-empty").is_empty());
}
