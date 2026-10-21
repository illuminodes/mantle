use mantle::primitives::{BlockHeight, Hash256, OutPoint, Satoshi};

use super::bip30::Bip30;
use super::block_coins::SpentCoin;
use super::script_checks::ScriptChecks;
use super::sequence_locks::SequenceLocks;
use super::sigop_cost::SigopCost;
use super::tx_script_context::Prevout;
use crate::chain_view::{ChainView, ConnectResult, ConnectScratch, NewCoin};
use crate::error::ValidationError;
use crate::script::ScriptFlags;
use crate::tx_view::{BlockView, InputView, OutputView, TxView};

// ── Constants ─────────────────────────────────────────────────────────────────

const INITIAL_SUBSIDY: Satoshi = Satoshi::new(50 * 100_000_000);
const HALVING_INTERVAL: u32 = 210_000;

/// Coinbase outputs must be at least this many blocks deep before they can be spent.
const COINBASE_MATURITY: u32 = 100;

// ── connect_block ─────────────────────────────────────────────────────────────

/// Stage 3: connect a block to the chain, checking UTXO-dependent rules.
///
/// Assumes Stage 1 and Stage 2 have already passed. Checks:
/// - BIP30: no tx creates an output that already exists unspent
/// - Every non-coinbase input exists in the UTXO set
/// - Coinbase maturity (100 blocks)
/// - Fee math: sum(inputs) >= sum(outputs) per tx; coinbase <= subsidy + fees
/// - Sigop cost budget (BIP141: legacy and P2SH sigops x4 plus witness sigops <= 80,000)
/// - BIP68 relative lock-times on version-2+ transactions
///
/// Returns a [`ConnectResult`] carrying the UTXO delta for the storage layer.
///
/// `scratch` is reused across txid computations to avoid repeated allocation.
///
/// `scripts` receives each transaction's script verification once that
/// transaction's other checks pass, and is drained after every other block
/// rule has passed. [`InlineScripts`](super::InlineScripts) verifies on the
/// calling thread, [`SkippedScripts`](super::SkippedScripts) skips scripts
/// for blocks under `assumevalid`, and a deferring implementation can verify
/// on other threads.
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
pub fn connect_block<'blk, 'v, 's, B, V, S>(
    block: &'blk B,
    height: BlockHeight,
    view: &'v V,
    scratch: &mut Vec<u8>,
    connect_scratch: &mut ConnectScratch,
    scripts: &mut S,
    precomputed_txids: Option<&[Hash256]>,
) -> Result<ConnectResult<'blk>, ValidationError>
where
    'blk: 's,
    'v: 's,
    B: BlockView,
    V: ChainView,
    S: ScriptChecks<'s>,
{
    if let Some(txids) = precomputed_txids {
        assert_eq!(
            txids.len(),
            block.tx_count(),
            "precomputed txids length must match block tx count",
        );
    }
    let bip30 = Bip30::new(height, block.header());
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

    let mut coins_scratch: Vec<Option<&'v crate::chain_view::Coin>> = {
        let v = std::mem::take(&mut connect_scratch.coins);
        // SAFETY: Option<&'static Coin> and Option<&'view Coin> have identical layout.
        // The vec is cleared inside get_coins_into before each use.
        unsafe {
            std::mem::transmute::<
                Vec<Option<&'static crate::chain_view::Coin>>,
                Vec<Option<&'v crate::chain_view::Coin>>,
            >(v)
        }
    };

    let mut total_fees = Satoshi::ZERO;
    let mut sigop_cost: u64 = 0;
    let count_p2sh = script_flags.contains(ScriptFlags::P2SH);
    let count_witness = script_flags.contains(ScriptFlags::WITNESS);
    connect_scratch.in_block.clear();
    let mut spent_coins: Vec<SpentCoin<'s>> = Vec::new();
    let mut prevouts: Vec<Prevout<'s>> = Vec::new();
    let sequence_locks = SequenceLocks::new(view, block.header(), height);

    for (tx_index, tx) in block.txs().enumerate() {
        let is_coinbase = tx_index == 0;
        let txid = match precomputed_txids {
            Some(txids) => txids[tx_index],
            None => tx.compute_txid(scratch)?,
        };

        bip30.check(view, tx, txid, tx_index)?;

        sigop_cost += SigopCost::legacy(tx) * SigopCost::WITNESS_SCALE_FACTOR;
        if sigop_cost > SigopCost::MAX_BLOCK_COST {
            return Err(ValidationError::SigopsLimitExceeded { cost: sigop_cost });
        }

        if is_coinbase {
            // Coinbase outputs go straight into created; no input lookup needed.
            for (vout, output) in tx.outputs().enumerate() {
                #[allow(clippy::cast_possible_truncation)]
                let outpoint = OutPoint {
                    txid,
                    vout: vout as u32,
                };
                connect_scratch
                    .in_block
                    .record_created(outpoint, created.len());
                created.push(NewCoin {
                    outpoint,
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

        spent_coins.clear();
        for (input_index, (outpoint, from_view)) in outpoints_scratch
            .iter()
            .zip(coins_scratch.iter())
            .enumerate()
        {
            let missing = ValidationError::MissingInput {
                tx_index,
                input_index,
            };
            if !connect_scratch.in_block.spend(*outpoint) {
                return Err(missing);
            }
            let coin = match connect_scratch.in_block.created_index(outpoint) {
                Some(i) => SpentCoin::from_block(&created[i]),
                None => SpentCoin::from_utxo(from_view.ok_or(missing)?),
            };
            spent_coins.push(coin);
        }

        for (input, coin) in tx.inputs().zip(spent_coins.iter()) {
            if count_p2sh {
                sigop_cost += SigopCost::p2sh(input.script_sig(), coin.script_pubkey)
                    * SigopCost::WITNESS_SCALE_FACTOR;
            }
            if count_witness {
                sigop_cost += SigopCost::witness(&input, coin.script_pubkey);
            }
        }
        if sigop_cost > SigopCost::MAX_BLOCK_COST {
            return Err(ValidationError::SigopsLimitExceeded { cost: sigop_cost });
        }

        sequence_locks.check(tx, &spent_coins, tx_index)?;

        let mut input_total = Satoshi::ZERO;
        for (input_index, (input, coin)) in tx.inputs().zip(spent_coins.iter()).enumerate() {
            if coin.coinbase {
                let depth = height.to_u32().saturating_sub(coin.height.to_u32());
                if depth < COINBASE_MATURITY {
                    return Err(ValidationError::CoinbaseMaturityViolation {
                        tx_index,
                        input_index,
                    });
                }
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

        if scripts.enabled() {
            prevouts.clear();
            prevouts.extend(spent_coins.iter().map(SpentCoin::prevout));
            scripts.check_tx(tx_index, tx, &prevouts, script_flags, scratch)?;
        }

        for (vout, output) in tx.outputs().enumerate() {
            #[allow(clippy::cast_possible_truncation)]
            let outpoint = OutPoint {
                txid,
                vout: vout as u32,
            };
            connect_scratch
                .in_block
                .record_created(outpoint, created.len());
            created.push(NewCoin {
                outpoint,
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

    scripts.finish()?;

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

// ── block_subsidy ─────────────────────────────────────────────────────────────

pub(super) fn block_subsidy(height: BlockHeight) -> Satoshi {
    let halvings = height.to_u32() / HALVING_INTERVAL;
    if halvings >= 64 {
        return Satoshi::ZERO;
    }
    Satoshi::new(INITIAL_SUBSIDY.to_u64() >> halvings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn count_legacy_sigops(script: &[u8]) -> u64 {
        SigopCost::count(script, false)
    }

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
