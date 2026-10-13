use super::LegacyScriptCode;

fn encoded(script: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    LegacyScriptCode::new(script).encode(&mut buf);
    buf
}

#[test]
fn a_script_without_separators_is_length_prefixed_unchanged() {
    let script = [0x76, 0xa9, 0x01, 0xab, 0x88, 0xac];
    let mut expected = vec![6];
    expected.extend_from_slice(&script);
    assert_eq!(encoded(&script), expected);
}

#[test]
fn separators_are_removed_and_the_length_shrinks() {
    assert_eq!(encoded(&[0xab, 0x76, 0xab, 0xac, 0xab]), vec![2, 0x76, 0xac]);
}

#[test]
fn a_separator_byte_inside_push_data_is_kept() {
    assert_eq!(encoded(&[0x02, 0xab, 0xab, 0xab]), vec![3, 0x02, 0xab, 0xab]);
}

#[test]
fn bytes_after_a_truncated_push_are_kept() {
    assert_eq!(encoded(&[0xab, 0x05, 0xab]), vec![2, 0x05, 0xab]);
}

#[test]
fn empty_script_encodes_as_zero_length() {
    assert_eq!(encoded(&[]), vec![0]);
}
