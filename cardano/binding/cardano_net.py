"""cardano_net.py - keyless Cardano (preview) access for the Chiral binding scripts. Recreates the
helper the original tooling expected, but with NO API key: a pycardano ChainContext backed by the
free Koios preview API (protocol params incl. PlutusV3 cost models, UTxOs, submit). Accounts load our
funded preview key from ~/.chiral/preview_relayer.key (bech32 ed25519_sk). Native aiken (no Docker).

Koios has no tx-evaluation endpoint, so Plutus redeemers must carry MANUAL ExUnits (our seal_nft is a
tiny one-shot mint; we set a safe fixed budget well under the per-tx limits).
"""
import os, sys, json, urllib.request, urllib.error, ssl
from fractions import Fraction
import pycardano as pc

KOIOS = os.environ.get("KOIOS_BASE", "https://preview.koios.rest/api/v1")
KEY_PATH = os.environ.get("CHIRAL_PREVIEW_KEY",
                          os.path.join(os.path.expanduser("~"), ".chiral", "preview_relayer.key"))
AIKEN = os.environ.get("AIKEN", os.path.join(os.path.expanduser("~"), ".aiken", "bin", "aiken"))
AIKEN_NATIVE = [AIKEN]  # invoke aiken directly (the original used a Docker wrapper)

def _urlopen_tolerant(req, timeout=45):
    """urlopen with normal TLS; if the peer cert is EXPIRED (Koios preview is currently serving a stale cert),
    retry once unverified with a warning. Testnet-only convenience: chain data is re-validated on submit and
    against the live chain (a tampered response causes a build/submit failure, never a key/fund compromise)."""
    try:
        return urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.URLError as e:
        if "CERTIFICATE_VERIFY_FAILED" in str(e) and "expired" in str(e):
            ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            print("WARN: Koios TLS cert expired; retrying unverified (testnet).", file=sys.stderr)
            return urllib.request.urlopen(req, timeout=timeout, context=ctx)
        raise

def _kget(path, body=None):
    req = urllib.request.Request(KOIOS + path,
        data=(json.dumps(body).encode() if body is not None else None),
        headers={"content-type": "application/json", "accept": "application/json"})
    return json.load(_urlopen_tolerant(req, 45))

def _ksubmit(cbor_bytes):
    req = urllib.request.Request(KOIOS + "/submittx", data=cbor_bytes,
        headers={"content-type": "application/cbor"})
    try:
        return _urlopen_tolerant(req, 60).read().decode().strip().strip('"')
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        raise RuntimeError(f"submit rejected ({e.code}): {body}") from None

# ---- bech32 decode (BIP173) for the ed25519_sk key ----
_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
def _bech32_decode(bech):
    bech = bech.strip().lower()
    pos = bech.rfind("1")
    data = [_CHARSET.find(c) for c in bech[pos+1:]]
    # drop 6-char checksum, convert 5-bit -> 8-bit
    acc = 0; bits = 0; out = bytearray()
    for v in data[:-6]:
        acc = (acc << 5) | v; bits += 5
        if bits >= 8:
            bits -= 8; out.append((acc >> bits) & 0xFF)
    return bytes(out)

def account(name="coordinator"):
    """Return (signing_key, verification_key, address) for our funded preview key. `name` is accepted
    for compatibility; all roles use the one funded key on testnet."""
    raw = _bech32_decode(open(KEY_PATH).read().strip())[:32]
    sk = pc.PaymentSigningKey.from_primitive(raw)
    vk = pc.PaymentVerificationKey.from_signing_key(sk)
    addr = pc.Address(vk.hash(), network=pc.Network.TESTNET)
    return sk, vk, addr


class KoiosChainContext(pc.ChainContext):
    def __init__(self):
        self._net = pc.Network.TESTNET
        self._pp = None; self._gp = None

    @property
    def network(self): return self._net
    @property
    def epoch(self): return int(_kget("/tip")[0]["epoch_no"])
    @property
    def last_block_slot(self): return int(_kget("/tip")[0]["abs_slot"])

    @property
    def genesis_param(self):
        if self._gp is None:
            self._gp = pc.GenesisParameters(
                active_slots_coefficient=0.05, update_quorum=5,
                max_lovelace_supply=45000000000000000, network_magic=2,
                epoch_length=86400, system_start=1666656000,
                slots_per_kes_period=129600, slot_length=1,
                max_kes_evolutions=62, security_param=2160)
        return self._gp

    @property
    def protocol_param(self):
        if self._pp is None:
            p = _kget("/epoch_params")[0]
            cm = p["cost_models"]
            cost_models = {lang: {i: int(v) for i, v in enumerate(vals)} for lang, vals in cm.items()}
            self._pp = pc.ProtocolParameters(
                min_fee_constant=int(p["min_fee_b"]), min_fee_coefficient=int(p["min_fee_a"]),
                max_block_size=int(p["max_block_size"]), max_tx_size=int(p["max_tx_size"]),
                max_block_header_size=int(p["max_bh_size"]),
                key_deposit=int(p["key_deposit"]), pool_deposit=int(p["pool_deposit"]),
                pool_influence=Fraction(str(p["influence"])),
                monetary_expansion=Fraction(str(p["monetary_expand_rate"])),
                treasury_expansion=Fraction(str(p["treasury_growth_rate"])),
                decentralization_param=Fraction(0, 1), extra_entropy="",
                protocol_major_version=int(p["protocol_major"]), protocol_minor_version=int(p["protocol_minor"]),
                min_utxo=1000000, min_pool_cost=int(p["min_pool_cost"]),
                price_mem=Fraction(str(p["price_mem"])), price_step=Fraction(str(p["price_step"])),
                max_tx_ex_mem=int(p["max_tx_ex_mem"]), max_tx_ex_steps=int(p["max_tx_ex_steps"]),
                max_block_ex_mem=int(p["max_block_ex_mem"]), max_block_ex_steps=int(p["max_block_ex_steps"]),
                max_val_size=int(p["max_val_size"]), collateral_percent=int(p["collateral_percent"]),
                max_collateral_inputs=int(p["max_collateral_inputs"]),
                coins_per_utxo_word=0, coins_per_utxo_byte=int(p["coins_per_utxo_size"]),
                cost_models=cost_models,
                maximum_reference_scripts_size={"bytes": 200000},
                min_fee_reference_scripts={"base": float(p["min_fee_ref_script_cost_per_byte"]),
                                           "range": 25600, "multiplier": 1.2})
        return self._pp

    def utxos(self, address):
        rows = _kget("/address_utxos", {"_addresses": [str(address)], "_extended": True})
        out = []
        for u in rows:
            if u.get("is_spent"):
                continue
            txin = pc.TransactionInput(pc.TransactionId(bytes.fromhex(u["tx_hash"])), int(u["tx_index"]))
            coin = int(u["value"])
            multi = pc.MultiAsset()
            for a in (u.get("asset_list") or []):
                pid = pc.ScriptHash(bytes.fromhex(a["policy_id"]))
                an = pc.AssetName(bytes.fromhex(a["asset_name"] or ""))
                multi.setdefault(pid, pc.Asset())[an] = int(a["quantity"])
            val = pc.Value(coin, multi) if len(multi) else pc.Value(coin)
            datum = None; datum_hash = None
            idat = u.get("inline_datum")
            if idat and idat.get("bytes"):
                # represent as a proper inline datum (RawPlutusData) so pycardano keeps it INLINE and does
                # NOT add it to the witness datum set (which would change the script_data_hash).
                datum = pc.RawPlutusData.from_cbor(bytes.fromhex(idat["bytes"]))
            elif u.get("datum_hash"):
                datum_hash = pc.DatumHash(bytes.fromhex(u["datum_hash"]))
            txout = pc.TransactionOutput(pc.Address.from_primitive(str(address)), val,
                                         datum=datum, datum_hash=datum_hash)
            out.append(pc.UTxO(txin, txout))
        return out

    def submit_tx_cbor(self, cbor):
        if isinstance(cbor, str):
            cbor = bytes.fromhex(cbor)
        return _ksubmit(cbor)

    def evaluate_tx_cbor(self, cbor):
        raise NotImplementedError("Koios has no tx evaluation; set redeemer ExUnits manually")


def chain_context():
    return KoiosChainContext()

def submit(tx, ctx):
    return ctx.submit_tx(tx)


if __name__ == "__main__":
    ctx = chain_context()
    sk, vk, addr = account()
    print("address:", addr)
    print("tip slot:", ctx.last_block_slot, "epoch:", ctx.epoch)
    us = ctx.utxos(str(addr))
    print("utxos:", len(us), "| total lovelace:", sum(int(u.output.amount.coin) for u in us))
    pp = ctx.protocol_param
    print("protocol_param OK; min_fee_a:", pp.min_fee_coefficient, "| cost_models langs:", list(pp.cost_models.keys()))
