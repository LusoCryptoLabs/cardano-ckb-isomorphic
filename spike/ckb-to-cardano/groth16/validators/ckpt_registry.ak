//// ckpt_registry.ak - E2: a STABLE, governor-gated checkpoint cell for the χADA RETURN leg, so the return
//// escrow no longer churns. Today the return re-ANCHORS the checkpoint per return (genesis_ckbcert mints a
//// FRESH thread NFT each time); because ada_escrow bakes the checkpoint NFT as a compile-time param, a new
//// NFT => new escrow script => ref scripts redeployed (~190 ADA) every return. This validator instead keeps
//// ONE checkpoint cell (one stable thread NFT, genesis-pinned once by the existing `ckbcert_thread`) and lets
//// the GOVERNOR re-anchor it IN PLACE: update {chain_root, total_difficulty, window_root, tip_height} to a
//// fresh anchor, preserving the lineage token, with a MONOTONIC tip. ada_escrow then bakes this STABLE NFT
//// and reads window_root/tip from this cell unchanged (canonical_cp is unmodified).
////
//// TRUST: this is a TRUSTED (no-PoW-proof) re-anchor - IDENTICAL trust to today's per-return re-genesis, which
//// already anchors a fresh tip on the relayer's say-so. The governor signature is that same authority, made
//// explicit; the monotonic-tip rule blocks an accidental rollback. (A truly trustless always-current
//// checkpoint is blocked by the per-block PoW proving wall - see CHECKPOINT_THROUGHPUT.md - so for the pilot
//// the trusted/periodic re-anchor is the realistic mechanism; advance_ckbcert remains the PoW-proven path for
//// the χCKB leg.) PoC; audit before value.
use aiken/builtin
use aiken/collection/list
use aiken/crypto.{VerificationKeyHash}
use cardano/address
use cardano/assets.{Value}
use cardano/transaction.{Transaction, OutputReference, Output, Input, InlineDatum}
use g16/ckbcert.{Checkpoint, lineage_token}

// The governor-authorized re-anchor: move the checkpoint to a fresh CKB anchor (no PoW proof - trusted).
pub type ReAnchor {
  new_chain_root: ByteArray,
  new_total_difficulty: ByteArray,
  new_window_root: ByteArray,
  new_tip_height: Int,
}

validator ckpt_registry(governor: VerificationKeyHash) {
  spend(datum: Option<Checkpoint>, redeemer: ReAnchor, own: OutputReference, tx: Transaction) {
    expect Some(cp) = datum
    let ReAnchor { new_chain_root, new_total_difficulty, new_window_root, new_tip_height } = redeemer
    // SEC B7 (verbatim from advance_ckbcert): pin lengths to 32 bytes so the cell's invariants stay well-formed.
    expect builtin.length_of_bytearray(new_chain_root) == 32
    expect builtin.length_of_bytearray(new_total_difficulty) == 32
    expect builtin.length_of_bytearray(new_window_root) == 32
    // 1) GOVERNOR-GATED: the re-anchor is authorized only by the governor key (the trusted re-anchor authority,
    //    same role that runs genesis_ckbcert today). No proof - this is the trusted advance.
    let signed = list.has(tx.extra_signatories, governor)
    // 2) CONTINUITY + MONOTONIC TIP (continuity form, verbatim from advance_ckbcert): the spent checkpoint must
    //    carry exactly one lineage thread token, and the single continuing output must keep the SAME token, carry
    //    the new state, and STRICTLY advance the tip (no rollback). The stable NFT therefore never changes, so the
    //    escrow that bakes it stays stable across every re-anchor.
    expect Some(self_in) = list.find(tx.inputs, fn(i) { i.output_reference == own })
    let cont_ok =
      when (lineage_token(self_in.output.value), continuing(tx, self_in.output)) is {
        (
          Some((tp, tn)),
          Some((out_value, Checkpoint { chain_root, total_difficulty, window_root, tip_height })),
        ) ->
          chain_root == new_chain_root && total_difficulty == new_total_difficulty && window_root == new_window_root && tip_height == new_tip_height && new_tip_height > cp.tip_height && lineage_token(
            out_value,
          ) == Some((tp, tn))
        _ -> False
      }
    signed && cont_ok
  }

  else(_) {
    fail
  }
}

/// The single continuing checkpoint output (same address as the spent cell): returns its value + datum.
/// SEC N1 (verbatim from advance_ckbcert): exactly ONE continuing output at the address - no decoy second cell.
fn continuing(tx: Transaction, self_out: Output) -> Option<(Value, Checkpoint)> {
  let addr = self_out.address
  when list.filter(tx.outputs, fn(o: Output) { o.address == addr }) is {
    [o] ->
      when o.datum is {
        InlineDatum(d) -> {
          expect c: Checkpoint = d
          Some((o.value, c))
        }
        _ -> None
      }
    _ -> None
  }
}

// ---- tests for the governor-gate + continuity/monotonic-tip wiring ----
const t_gov: VerificationKeyHash = #"2df44c712df44c712df44c712df44c712df44c712df44c712df44c71"
const t_pol: assets.PolicyId = #"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
const t_thread: ByteArray = #"636b62636572742d746872656164"
const t_script: ByteArray = #"b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"
const t_r32: ByteArray = #"3333333333333333333333333333333333333333333333333333333333333333"
const t_d_old: ByteArray = #"0000000000000000000000000000000000000000000000000000000000000064"
const t_d_new: ByteArray = #"00000000000000000000000000000000000000000000000000000000000000c8"
const t_w_new: ByteArray = #"4444444444444444444444444444444444444444444444444444444444444444"
const t_own: OutputReference =
  OutputReference { transaction_id: #"00000000000000000000000000000000000000000000000000000000000000aa", output_index: 0 }

fn cp(tip: Int) -> Checkpoint {
  Checkpoint { chain_root: t_r32, total_difficulty: t_d_old, window_root: t_r32, tip_height: tip }
}

fn cell(val: Value, c: Checkpoint) -> Output {
  Output {
    address: address.Address { payment_credential: address.Script(t_script), stake_credential: None },
    value: val,
    datum: InlineDatum(c),
    reference_script: None,
  }
}

fn reanchor_tx(signers: List<VerificationKeyHash>, in_val: Value, out_val: Value, out_tip: Int) -> Transaction {
  let in_cell = cell(in_val, cp(100))
  Transaction {
    ..transaction.placeholder,
    inputs: [Input { output_reference: t_own, output: in_cell }],
    outputs: [cell(out_val, Checkpoint { chain_root: t_r32, total_difficulty: t_d_new, window_root: t_w_new, tip_height: out_tip })],
    extra_signatories: signers,
  }
}

fn reanchor() -> ReAnchor {
  ReAnchor { new_chain_root: t_r32, new_total_difficulty: t_d_new, new_window_root: t_w_new, new_tip_height: 112 }
}

// governor-signed, lineage preserved, tip advances 100 -> 112: accepted.
test reanchor_ok() {
  let v = assets.from_asset(t_pol, t_thread, 1)
  ckpt_registry.spend(t_gov, Some(cp(100)), reanchor(), t_own, reanchor_tx([t_gov], v, v, 112))
}

// not signed by the governor: rejected.
test reanchor_unsigned_rejected() {
  let v = assets.from_asset(t_pol, t_thread, 1)
  !ckpt_registry.spend(t_gov, Some(cp(100)), reanchor(), t_own, reanchor_tx([], v, v, 112))
}

// tip rollback (new tip <= old tip): rejected even when governor-signed.
test reanchor_rollback_rejected() {
  let v = assets.from_asset(t_pol, t_thread, 1)
  let r = ReAnchor { ..reanchor(), new_tip_height: 100 }
  !ckpt_registry.spend(t_gov, Some(cp(100)), r, t_own, reanchor_tx([t_gov], v, v, 100))
}

// lineage token dropped on the continuing output (no NFT): rejected (the stable NFT must be preserved).
test reanchor_token_dropped_rejected() {
  let v = assets.from_asset(t_pol, t_thread, 1)
  !ckpt_registry.spend(t_gov, Some(cp(100)), reanchor(), t_own, reanchor_tx([t_gov], v, assets.from_lovelace(2_000_000), 112))
}
