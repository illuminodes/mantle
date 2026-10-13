use super::FindAndDelete;

fn delete(script: &[u8], sig: &[u8]) -> Vec<u8> {
    FindAndDelete::for_push(sig).apply(script).into_owned()
}

#[test]
fn removes_every_minimal_push_of_the_signature() {
    let script = [0x03, 0xaa, 0xbb, 0xcc, 0x76, 0x03, 0xaa, 0xbb, 0xcc, 0x75];
    assert_eq!(delete(&script, &[0xaa, 0xbb, 0xcc]), vec![0x76, 0x75]);
}

#[test]
fn removes_back_to_back_pushes() {
    let script = [0x01, 0xaa, 0x01, 0xaa, 0x76];
    assert_eq!(delete(&script, &[0xaa]), vec![0x76]);
}

#[test]
fn a_longer_push_containing_the_signature_is_kept() {
    let script = [0x04, 0xaa, 0xbb, 0xcc, 0xdd];
    assert_eq!(delete(&script, &[0xaa, 0xbb, 0xcc]), script.to_vec());
}

#[test]
fn a_non_minimal_push_of_the_signature_is_kept() {
    let script = [0x4c, 0x03, 0xaa, 0xbb, 0xcc, 0x76];
    assert_eq!(delete(&script, &[0xaa, 0xbb, 0xcc]), script.to_vec());
}

#[test]
fn a_pushdata1_signature_is_matched_in_its_canonical_form() {
    let sig = [0x5a; 0x50];
    let mut script = vec![0x4c, 0x50];
    script.extend_from_slice(&sig);
    script.push(0x76);
    assert_eq!(delete(&script, &sig), vec![0x76]);
}

#[test]
fn an_empty_signature_deletes_op_zero() {
    assert_eq!(delete(&[0x00, 0x76, 0x00], &[]), vec![0x76]);
}

#[test]
fn matches_only_at_opcode_boundaries() {
    let script = [0x02, 0x01, 0xaa, 0x76];
    assert_eq!(delete(&script, &[0xaa]), script.to_vec());
}

#[test]
fn a_truncated_push_ends_the_scan_and_is_copied_verbatim() {
    let script = [0x01, 0xaa, 0x05, 0x01, 0xaa];
    assert_eq!(delete(&script, &[0xaa]), vec![0x05, 0x01, 0xaa]);
}

#[test]
fn no_match_borrows_the_input() {
    let script = [0x76, 0xa9];
    assert!(matches!(
        FindAndDelete::for_push(&[0xaa]).apply(&script),
        std::borrow::Cow::Borrowed(_)
    ));
}
