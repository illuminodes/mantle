use std::ffi::{CString, c_char, c_int, c_uchar, c_uint};
use std::io::{Cursor, Read};
use std::ptr;

use mantle::codec::Decode;
use mantle::primitives::{Block, Satoshi, Transaction};
use mantle_consensus::script::flags::ScriptFlags;
use mantle_consensus::script::verify::{
    SpentOutputs, is_push_only, verify_script_with_spent_outputs, witness_program_of,
};
use mantle_consensus::validation::SigopCost;

fn to_c_string(s: &str) -> *mut c_char {
    CString::new(s).map_or(ptr::null_mut(), CString::into_raw)
}

/// Read a Bitcoin-canonical CompactSize + payload, rejecting non-canonical encodings.
/// Matches Core's `ReadCompactSize` behaviour.
fn read_compact_script(data: &[u8]) -> Option<Vec<u8>> {
    let mut cursor = Cursor::new(data);
    let mut tag = [0u8; 1];
    cursor.read_exact(&mut tag).ok()?;

    let (len, header_size): (u64, u64) = match tag[0] {
        0xfd => {
            let mut buf = [0u8; 2];
            cursor.read_exact(&mut buf).ok()?;
            let v = u16::from_le_bytes(buf);
            if v < 253 {
                return None;
            }
            (u64::from(v), 3)
        }
        0xfe => {
            let mut buf = [0u8; 4];
            cursor.read_exact(&mut buf).ok()?;
            let v = u32::from_le_bytes(buf);
            if v < 0x10000 {
                return None;
            }
            (u64::from(v), 5)
        }
        0xff => {
            let mut buf = [0u8; 8];
            cursor.read_exact(&mut buf).ok()?;
            let v = u64::from_le_bytes(buf);
            if v < 0x1_0000_0000 {
                return None;
            }
            (v, 9)
        }
        n => (u64::from(n), 1),
    };

    let len = usize::try_from(len).ok()?;
    let remaining = data.len() - header_size as usize;
    if len > remaining {
        return None;
    }
    let start = header_size as usize;
    Some(data[start..start + len].to_vec())
}

/// # Safety
/// `s` must be null or a pointer previously returned by a `mantle_*` function.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mantle_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            drop(CString::from_raw(s));
        }
    }
}

/// # Safety
/// `data` must point to `len` readable bytes (or be null).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mantle_script_parse(data: *const c_uchar, len: usize) -> *mut c_char {
    if data.is_null() || len == 0 {
        return to_c_string("0");
    }
    let bytes = unsafe { std::slice::from_raw_parts(data, len) };

    let script_bytes = match read_compact_script(bytes) {
        Some(b) => b,
        None => return to_c_string("0"),
    };

    if script_bytes.len() > 10_000 {
        return to_c_string("0");
    }

    // Core's IsUnspendable: OP_RETURN or script > MAX_SCRIPT_SIZE
    if script_bytes.first() == Some(&0x6a) {
        return to_c_string("0");
    }

    let sigops = SigopCost::count(&script_bytes, false);
    let is_witness = if witness_program_of(&script_bytes).is_some() {
        "1"
    } else {
        "0"
    };
    let push_only = if is_push_only(&script_bytes) {
        "1"
    } else {
        "0"
    };

    let result = format!("{sigops}{is_witness}{push_only}");
    to_c_string(&result)
}

/// # Safety
/// `data` must point to `len` readable bytes (or be null).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mantle_deserialize_block(data: *const c_uchar, len: usize) -> *mut c_char {
    if data.is_null() || len == 0 {
        return ptr::null_mut();
    }
    let bytes = unsafe { std::slice::from_raw_parts(data, len) };

    let block = match Block::decode(&mut Cursor::new(bytes)) {
        Ok(b) => b,
        Err(_) => return ptr::null_mut(),
    };

    let hash = block.header.hash();
    to_c_string(&hash.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crash_0x50_divergence() {
        let input: &[u8] = &[0x04, 0x50, 0x00, 0x00, 0x00];

        let script = read_compact_script(input).expect("should decode");
        assert_eq!(script, vec![0x50, 0x00, 0x00, 0x00]);

        let sigops = SigopCost::count(&script, false);
        let witness = witness_program_of(&script).is_some();
        let push = is_push_only(&script);

        let result = format!(
            "{sigops}{}{}",
            if witness { "1" } else { "0" },
            if push { "1" } else { "0" }
        );
        // Core returns "001" — sigops=0, witness=false, push_only=true
        assert_eq!(
            result, "001",
            "must match Core: sigops={sigops} witness={witness} push_only={push}"
        );
    }
}

/// # Safety
/// All pointer arguments must point to their declared lengths of readable bytes,
/// or be null (in which case the corresponding length must be 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mantle_verify_script(
    script_pubkey: *const c_uchar,
    script_pubkey_len: usize,
    amount: u64,
    tx_data: *const c_uchar,
    tx_data_len: usize,
    input_idx: c_uint,
    flags: c_uint,
    spent_amounts: *const u64,
    spent_scripts: *const *const c_uchar,
    spent_script_lens: *const usize,
    n_spent: usize,
) -> c_int {
    if script_pubkey.is_null() || tx_data.is_null() {
        return -1;
    }
    let spk = unsafe { std::slice::from_raw_parts(script_pubkey, script_pubkey_len) };
    let tx_bytes = unsafe { std::slice::from_raw_parts(tx_data, tx_data_len) };

    let tx = match Transaction::decode(&mut Cursor::new(tx_bytes)) {
        Ok(t) => t,
        Err(_) => return -1,
    };

    let n_in = input_idx as usize;
    if n_in >= tx.inputs.len() {
        return -1;
    }

    let script_flags = ScriptFlags::from_bits(flags);

    if !spent_amounts.is_null()
        && !spent_scripts.is_null()
        && !spent_script_lens.is_null()
        && n_spent > 0
    {
        let amounts_raw = unsafe { std::slice::from_raw_parts(spent_amounts, n_spent) };
        let scripts_raw = unsafe { std::slice::from_raw_parts(spent_scripts, n_spent) };
        let lens_raw = unsafe { std::slice::from_raw_parts(spent_script_lens, n_spent) };

        let sat_amounts: Vec<Satoshi> = amounts_raw.iter().map(|&a| Satoshi::new(a)).collect();
        let script_slices: Vec<&[u8]> = (0..n_spent)
            .map(|j| unsafe { std::slice::from_raw_parts(scripts_raw[j], lens_raw[j]) })
            .collect();

        if let Some(spent_outputs) = SpentOutputs::new(&sat_amounts, &script_slices) {
            match verify_script_with_spent_outputs(
                tx.inputs[n_in].script_sig.as_slice(),
                spk,
                &tx,
                n_in,
                Satoshi::new(amount),
                script_flags,
                spent_outputs,
            ) {
                Ok(()) => return 1,
                Err(_) => return 0,
            }
        }
    }

    match mantle_consensus::script::verify::verify_script(
        tx.inputs[n_in].script_sig.as_slice(),
        spk,
        &tx,
        n_in,
        Satoshi::new(amount),
        script_flags,
    ) {
        Ok(()) => 1,
        Err(_) => 0,
    }
}
