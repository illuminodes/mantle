use mantle::primitives::{BlockHeight, Hash256, OutPoint, Satoshi};

use crate::chain_view::{ChainView, ConnectResult, ConnectScratch, NewCoin};
use crate::error::ValidationError;
use super::tx_script_context::TxScriptContext;
use crate::script::{ScriptExecutionCache, ScriptFlags};
use crate::tx_view::{BlockView, InputView, OutputView, TxView};

// ── Constants ─────────────────────────────────────────────────────────────────

const INITIAL_SUBSIDY: Satoshi = Satoshi::new(50 * 100_000_000);
const HALVING_INTERVAL: u32 = 210_000;

/// Coinbase outputs must be at least this many blocks deep before they can be spent.
const COINBASE_MATURITY: u32 = 100;

/// Maximum legacy sigops per block.
const MAX_BLOCK_SIGOPS: u32 = 20_000;

/// Heights of the two historical BIP30 exception blocks on mainnet.
/// These coinbase txids collide with earlier unspent coinbases but were
/// accepted by Core before BIP30 enforcement began.
const BIP30_EXCEPTION_HEIGHTS: [BlockHeight; 2] =
    [BlockHeight::new(91_842), BlockHeight::new(91_880)];

// ── connect_block ─────────────────────────────────────────────────────────────

/// Stage 3: connect a block to the chain, checking UTXO-dependent rules.
///
/// Assumes Stage 1 and Stage 2 have already passed. Checks:
/// - BIP30: no tx shares a txid with an existing unspent coinbase
/// - Every non-coinbase input exists in the UTXO set
/// - Coinbase maturity (100 blocks)
/// - Fee math: sum(inputs) >= sum(outputs) per tx; coinbase <= subsidy + fees
/// - Legacy sigops budget (<= 20,000 per block)
///
/// Returns a [`ConnectResult`] carrying the UTXO delta for the storage layer.
///
/// `scratch` is reused across txid computations to avoid repeated allocation.
///
/// `skip_script` — when `true`, script verification is skipped entirely for
/// all inputs. Set this for blocks at or below the `assumevalid` tip: all
/// other consensus checks (UTXO, maturity, fee math, sigops) still run.
///
/// `exec_cache` — optional [`ScriptExecutionCache`]. When `Some`, each input
/// probes the cache before running the interpreter; hits short-circuit the
/// full verification. Pass `None` to disable caching (fuzzer, tests).
///
/// `precomputed_txids` — optional pre-hashed per-tx ids in block order. The
/// pipeline computes txids before validation (for intra-block dep collection,
/// BIP30 probes, etc.); passing them here lets `connect_block` skip its own
/// txid pass and reuse the same hashes. Length must equal `block.tx_count()`.
/// Pass `None` to compute internally (legacy / single-block test paths).
///
/// # Errors
/// Returns the first [`ValidationError`] encountered.
///
/// # Panics
/// Panics if `precomputed_txids` is `Some(slice)` and `slice.len() != block.tx_count()`.
#[allow(clippy::too_many_lines)] // single-pass per-input loop reads better as one function
#[allow(clippy::too_many_arguments)] // precomputed_txids is opt-in; refactoring to a struct adds churn
pub fn connect_block<'blk, B, V>(
    block: &'blk B,
    height: BlockHeight,
    view: &V,
    scratch: &mut Vec<u8>,
    connect_scratch: &mut ConnectScratch,
    skip_script: bool,
    mut exec_cache: Option<&mut ScriptExecutionCache>,
    precomputed_txids: Option<&[Hash256]>,
) -> Result<ConnectResult<'blk>, ValidationError>
where
    B: BlockView,
    V: ChainView,
{
    if let Some(txids) = precomputed_txids {
        assert_eq!(
            txids.len(),
            block.tx_count(),
            "precomputed txids length must match block tx count",
        );
    }
    let is_bip30_exception = BIP30_EXCEPTION_HEIGHTS.contains(&height);
    let subsidy = block_subsidy(height);
    let script_flags = ScriptFlags::for_height(height);

    // Reclaim scratch vecs from ConnectScratch. The `created` and `coins`
    // vecs are stored as `'static` between calls; transmute to the block
    // lifetime here. This is safe: NewCoin's layout is lifetime-invariant
    // (just a pointer+len for script_pubkey), and we clear before filling.
    let total_outputs: usize = block.txs().map(TxView::output_count).sum();
    let mut created: Vec<NewCoin<'blk>> = {
        let mut v = std::mem::take(&mut connect_scratch.created);
        v.clear();
        v.reserve(total_outputs.saturating_sub(v.capacity()));
        // SAFETY: NewCoin<'static> and NewCoin<'blk> have identical layout.
        unsafe { std::mem::transmute::<Vec<NewCoin<'static>>, Vec<NewCoin<'blk>>>(v) }
    };

    connect_scratch.spent.clear();
    let outpoints_scratch = &mut connect_scratch.outpoints;

    let mut coins_scratch: Vec<Option<&crate::chain_view::Coin>> = {
        let v = std::mem::take(&mut connect_scratch.coins);
        // SAFETY: Option<&'static Coin> and Option<&'view Coin> have identical layout.
        // The vec is cleared inside get_coins_into before each use.
        unsafe {
            std::mem::transmute::<
                Vec<Option<&'static crate::chain_view::Coin>>,
                Vec<Option<&crate::chain_view::Coin>>,
            >(v)
        }
    };

    let mut total_fees = Satoshi::ZERO;
    let mut total_sigops: u32 = 0;

    for (tx_index, tx) in block.txs().enumerate() {
        let is_coinbase = tx_index == 0;
        let txid = match precomputed_txids {
            Some(txids) => txids[tx_index],
            None => tx.compute_txid(scratch)?,
        };

        // BIP30: if any output of this tx is at a txid that already has an
        // unspent coinbase in the UTXO set, reject (unless this is an exception height).
        if !is_bip30_exception {
            let bip30_probe = OutPoint { txid, vout: 0 };
            if let Some(coin) = view.get_coin(&bip30_probe)?
                && coin.coinbase
            {
                return Err(ValidationError::Bip30Violation { tx_index });
            }
        }

        // Legacy sigops: count OP_CHECKSIG / OP_CHECKMULTISIG in scriptSig and
        // scriptPubKey. Each OP_CHECKMULTISIG counts as 20 (MAX_PUBKEYS_PER_MULTISIG).
        for input in tx.inputs() {
            total_sigops = total_sigops.saturating_add(count_legacy_sigops(input.script_sig()));
        }
        for output in tx.outputs() {
            total_sigops = total_sigops.saturating_add(count_legacy_sigops(output.script_pubkey()));
        }
        if total_sigops > MAX_BLOCK_SIGOPS {
            return Err(ValidationError::SigopsLimitExceeded {
                count: total_sigops,
            });
        }

        if is_coinbase {
            // Coinbase outputs go straight into created; no input lookup needed.
            for (vout, output) in tx.outputs().enumerate() {
                #[allow(clippy::cast_possible_truncation)]
                created.push(NewCoin {
                    outpoint: OutPoint {
                        txid,
                        vout: vout as u32,
                    },
                    value: output.value(),
                    script_pubkey: output.script_pubkey(),
                    coinbase: true,
                    height,
                });
            }
            // Coinbase reward is validated after we know total_fees (below).
            continue;
        }

        // Non-coinbase: look up every input in the UTXO set. Reuse both
        // scratch vecs instead of allocating per tx.
        outpoints_scratch.clear();
        outpoints_scratch.extend(tx.inputs().map(|i| i.previous_output()));
        view.get_coins_into(outpoints_scratch, &mut coins_scratch)?;
        let coins = &coins_scratch;

        let script_ctx = if skip_script {
            None
        } else {
            Some(TxScriptContext::new(
                tx,
                coins,
                script_flags,
                exec_cache.is_some(),
                scratch,
            )?)
        };

        let mut input_total = Satoshi::ZERO;
        for (input_index, (input, coin_opt)) in tx.inputs().zip(coins.iter()).enumerate() {
            let coin = coin_opt.as_ref().ok_or(ValidationError::MissingInput {
                tx_index,
                input_index,
            })?;

            // Coinbase maturity: coinbase outputs must be 100 blocks deep.
            if coin.coinbase {
                let depth = height.to_u32().saturating_sub(coin.height.to_u32());
                if depth < COINBASE_MATURITY {
                    return Err(ValidationError::CoinbaseMaturityViolation {
                        tx_index,
                        input_index,
                    });
                }
            }

            // Script verification: fourth per-input check, after coin lookup,
            // before fee math. Skipped entirely under assumevalid (`skip_script`).
            // When a cache is provided, probes it before running the interpreter.
            if let Some(ctx) = &script_ctx {
                ctx.verify_input(
                    tx,
                    input_index,
                    input.script_sig(),
                    coin,
                    exec_cache.as_deref_mut(),
                )
                .map_err(|kind| ValidationError::ScriptVerifyFailed {
                    tx_index,
                    input_index,
                    kind,
                })?;
            }

            input_total = input_total
                .checked_add(coin.value)
                .ok_or(ValidationError::InputValueOverflow { tx_index })?;

            connect_scratch.spent.push(input.previous_output());
        }

        let output_total = tx
            .outputs()
            .try_fold(Satoshi::ZERO, |acc, o| acc.checked_add(o.value()))
            .ok_or(ValidationError::InputValueOverflow { tx_index })?;

        if output_total > input_total {
            return Err(ValidationError::NegativeFee { tx_index });
        }

        let fee = input_total - output_total;
        total_fees = total_fees
            .checked_add(fee)
            .ok_or(ValidationError::InputValueOverflow { tx_index })?;

        for (vout, output) in tx.outputs().enumerate() {
            #[allow(clippy::cast_possible_truncation)]
            created.push(NewCoin {
                outpoint: OutPoint {
                    txid,
                    vout: vout as u32,
                },
                value: output.value(),
                script_pubkey: output.script_pubkey(),
                coinbase: false,
                height,
            });
        }
    }

    // Validate coinbase reward against subsidy + fees.
    let coinbase_output_total = block
        .tx(0)
        .outputs()
        .try_fold(Satoshi::ZERO, |acc, o| acc.checked_add(o.value()))
        .ok_or(ValidationError::CoinbaseRewardExceedsSubsidy)?;

    let max_coinbase = subsidy
        .checked_add(total_fees)
        .ok_or(ValidationError::CoinbaseRewardExceedsSubsidy)?;

    if coinbase_output_total > max_coinbase {
        return Err(ValidationError::CoinbaseRewardExceedsSubsidy);
    }

    let spent = std::mem::take(&mut connect_scratch.spent);

    // Return coins_scratch to ConnectScratch (capacity preserved for next call).
    coins_scratch.clear();
    connect_scratch.coins = unsafe {
        std::mem::transmute::<
            Vec<Option<&crate::chain_view::Coin>>,
            Vec<Option<&'static crate::chain_view::Coin>>,
        >(coins_scratch)
    };
    // `created` ownership moves into ConnectResult. Caller should call
    // `ConnectScratch::reclaim()` after consuming the result to return
    // both `created` and `spent` capacity for the next block.

    Ok(ConnectResult {
        created,
        spent,
        fees: total_fees,
    })
}

// ── BlockHeightExt ────────────────────────────────────────────────────────────

/// Extension trait that adds `subsidy()` to [`BlockHeight`].
pub trait BlockHeightExt {
    /// Block reward subsidy in satoshis at this height.
    fn subsidy(self) -> Satoshi;
}

impl BlockHeightExt for BlockHeight {
    fn subsidy(self) -> Satoshi {
        block_subsidy(self)
    }
}

// ── block_subsidy / count_legacy_sigops ───────────────────────────────────────

pub(super) fn block_subsidy(height: BlockHeight) -> Satoshi {
    let halvings = height.to_u32() / HALVING_INTERVAL;
    if halvings >= 64 {
        return Satoshi::ZERO;
    }
    Satoshi::new(INITIAL_SUBSIDY.to_u64() >> halvings)
}

/// Count legacy sigops (`OP_CHECKSIG` + `OP_CHECKSIGVERIFY` + `OP_CHECKMULTISIG` family)
/// in a raw script byte slice.
///
/// `OP_CHECKMULTISIG` / `OP_CHECKMULTISIGVERIFY` each count as 20 (the maximum
/// allowed pubkeys per multisig), matching Core's pre-segwit counting rule.
///
/// # Panics
/// Panics if an `OP_PUSHDATA4` length field exceeds `usize::MAX` (impossible on
/// 32-bit or wider platforms).
#[must_use]
pub fn count_legacy_sigops(script: &[u8]) -> u32 {
    const OP_CHECKSIG: u8 = 0xac;
    const OP_CHECKSIGVERIFY: u8 = 0xad;
    const OP_CHECKMULTISIG: u8 = 0xae;
    const OP_CHECKMULTISIGVERIFY: u8 = 0xaf;

    let mut count: u32 = 0;
    let mut i = 0;
    while i < script.len() {
        let op = script[i];
        match op {
            OP_CHECKSIG | OP_CHECKSIGVERIFY => count += 1,
            OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => count += 20,
            // Push data opcodes: skip the pushed bytes.
            0x01..=0x4b => i += usize::from(op),
            0x4c => {
                // OP_PUSHDATA1: next byte is length
                if let Some(&len) = script.get(i + 1) {
                    i += 1 + usize::from(len);
                } else {
                    break;
                }
            }
            0x4d => {
                // OP_PUSHDATA2: next 2 bytes are little-endian length
                if i + 2 < script.len() {
                    let len = usize::from(u16::from_le_bytes([script[i + 1], script[i + 2]]));
                    i += 2 + len;
                } else {
                    break;
                }
            }
            0x4e => {
                // OP_PUSHDATA4: next 4 bytes are little-endian length
                if i + 4 < script.len() {
                    let len = usize::try_from(u32::from_le_bytes([
                        script[i + 1],
                        script[i + 2],
                        script[i + 3],
                        script[i + 4],
                    ]))
                    .expect("script push length overflows usize");
                    i += 4 + len;
                } else {
                    break;
                }
            }
            _ => {}
        }
        i += 1;
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sigops_empty_script() {
        assert_eq!(count_legacy_sigops(&[]), 0);
    }

    #[test]
    fn sigops_single_checksig() {
        assert_eq!(count_legacy_sigops(&[0xac]), 1);
    }

    #[test]
    fn sigops_checksigverify() {
        assert_eq!(count_legacy_sigops(&[0xad]), 1);
    }

    #[test]
    fn sigops_checkmultisig_counts_20() {
        assert_eq!(count_legacy_sigops(&[0xae]), 20);
    }

    #[test]
    fn sigops_checkmultisigverify_counts_20() {
        assert_eq!(count_legacy_sigops(&[0xaf]), 20);
    }

    #[test]
    fn sigops_mixed() {
        // OP_CHECKSIG + OP_CHECKMULTISIG + OP_CHECKSIGVERIFY = 1 + 20 + 1 = 22
        assert_eq!(count_legacy_sigops(&[0xac, 0xae, 0xad]), 22);
    }

    #[test]
    fn sigops_push_skips_data() {
        // Push 3 bytes (which happen to look like OP_CHECKSIG), then actual OP_CHECKSIG
        // 0x03 <0xac 0xac 0xac> 0xac → only the trailing one counts
        assert_eq!(count_legacy_sigops(&[0x03, 0xac, 0xac, 0xac, 0xac]), 1);
    }

    #[test]
    fn sigops_pushdata1_skips_data() {
        // OP_PUSHDATA1 <len=2> <0xac 0xac> 0xac → 1
        assert_eq!(count_legacy_sigops(&[0x4c, 0x02, 0xac, 0xac, 0xac]), 1);
    }

    #[test]
    fn sigops_pushdata2_skips_data() {
        // OP_PUSHDATA2 <len=1, 0> <0xac> 0xac → 1
        assert_eq!(count_legacy_sigops(&[0x4d, 0x01, 0x00, 0xac, 0xac]), 1);
    }

    #[test]
    fn sigops_pushdata4_skips_data() {
        // OP_PUSHDATA4 <len=1, 0, 0, 0> <0xac> 0xac → 1
        assert_eq!(
            count_legacy_sigops(&[0x4e, 0x01, 0x00, 0x00, 0x00, 0xac, 0xac]),
            1
        );
    }

    #[test]
    fn sigops_truncated_pushdata1_stops() {
        // OP_PUSHDATA1 at end of script — no length byte → 0
        assert_eq!(count_legacy_sigops(&[0x4c]), 0);
    }

    #[test]
    fn sigops_truncated_pushdata2_stops() {
        // OP_PUSHDATA2 with only 1 length byte → 0
        assert_eq!(count_legacy_sigops(&[0x4d, 0x01]), 0);
    }

    #[test]
    fn sigops_no_sigops_in_plain_script() {
        // OP_DUP OP_HASH160 OP_EQUALVERIFY — no sigops
        assert_eq!(count_legacy_sigops(&[0x76, 0xa9, 0x88]), 0);
    }

    #[test]
    fn subsidy_at_genesis() {
        assert_eq!(
            block_subsidy(BlockHeight::ZERO),
            Satoshi::new(50 * 100_000_000)
        );
    }

    #[test]
    fn subsidy_first_halving() {
        assert_eq!(
            block_subsidy(BlockHeight::new(210_000)),
            Satoshi::new(25 * 100_000_000)
        );
    }

    #[test]
    fn subsidy_after_64_halvings_is_zero() {
        assert_eq!(block_subsidy(BlockHeight::new(64 * 210_000)), Satoshi::ZERO);
    }
}
