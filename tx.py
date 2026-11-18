COIN_AMOUNTS = [50000, 30000]
PAY_AMOUNTS = [60000]
FEE_RATE = 5
SIGHASH = "ALL"

import hashlib

import bech32
import secp256k1
from ripemd160 import ripemd160
from sign import BIP143_TEST_KEY, der, sign, verify

SIGHASH_TYPES = {
    "ALL": 0x01,
    "NONE": 0x02,
    "SINGLE": 0x03,
    "ALL|ANYONECANPAY": 0x81,
    "NONE|ANYONECANPAY": 0x82,
    "SINGLE|ANYONECANPAY": 0x83,
}
DUST = 294
MAX_FEE = 10000
MAX_AMOUNT = 100000000
VERSION = 2
SEQUENCE = 0xFFFFFFFD
LOCKTIME = 0


def sha256(data):
    return hashlib.sha256(data).digest()


def double_sha256(data):
    return sha256(sha256(data))


def hash160(data):
    return ripemd160(sha256(data))


def number(value, size):
    return value.to_bytes(size, "little")


def count(value):
    if value < 0xFD:
        return bytes([value])
    return b"\xfd" + number(value, 2)


def with_length(data):
    return count(len(data)) + data


def locking_script(public_key):
    return b"\x00\x14" + hash160(public_key)


def test_address(public_key):
    return bech32.segwit_address("tb", 0, list(hash160(public_key)))


def made_up_coin(index):
    return double_sha256(f"CryptoNoobs made-up coin {index + 1}".encode())


def recipient_key(index):
    key = int.from_bytes(sha256(f"CryptoNoobs recipient {index + 1}".encode()), "big")
    return secp256k1.public_key(key)


def size_estimate(inputs, outputs):
    base = 4 + 1 + inputs * 41 + 1 + outputs * 31 + 4
    witness = 2 + inputs * (1 + 1 + 73 + 1 + 33)
    return (base * 4 + witness + 3) // 4


def stop(message):
    print(message)
    raise SystemExit(1)


def check_settings():
    if len(COIN_AMOUNTS) < 1 or len(COIN_AMOUNTS) > 4:
        stop("Use 1 to 4 coins.")
    if len(PAY_AMOUNTS) < 1 or len(PAY_AMOUNTS) > 4:
        stop("Pay 1 to 4 outputs.")
    if SIGHASH not in SIGHASH_TYPES:
        stop("SIGHASH must be one of: " + ", ".join(SIGHASH_TYPES))
    if FEE_RATE not in [2, 5, 20]:
        stop("FEE_RATE must be one of the example rates 2, 5 or 20 sat/vB.")
    for amount in COIN_AMOUNTS + PAY_AMOUNTS:
        if not isinstance(amount, int) or amount < 1 or amount > MAX_AMOUNT:
            stop(f"Every amount must be a whole number of sat from 1 to {MAX_AMOUNT}.")
    for amount in PAY_AMOUNTS:
        if amount < DUST:
            stop(f"An output of {amount} sat is below the dust limit of {DUST} sat.")


def plan():
    total_in = sum(COIN_AMOUNTS)
    total_pay = sum(PAY_AMOUNTS)
    vbytes = size_estimate(len(COIN_AMOUNTS), len(PAY_AMOUNTS) + 1)
    fee = FEE_RATE * vbytes
    change = total_in - total_pay - fee
    if total_pay >= total_in:
        stop("The outputs use up every sat of the coins, so nothing is left for the fee or the change.")
    if change < 0:
        stop(f"The fee would be {fee} sat, but only {total_in - total_pay} sat is left. Lower an output.")
    if fee > MAX_FEE:
        stop(f"The fee would be {fee} sat, above the {MAX_FEE} sat this file allows.")
    if change < DUST:
        stop(f"The change would be {change} sat, below the dust limit of {DUST} sat. Lower an output.")
    return fee, change


def sighash(inputs, outputs, index, public_key, amount, sighash_type):
    base = sighash_type & 0x1F
    anyone = sighash_type & 0x80
    zero = bytes(32)
    if anyone:
        hash_prevouts = zero
    else:
        hash_prevouts = double_sha256(b"".join(txid + number(vout, 4) for txid, vout in inputs))
    if anyone or base != 0x01:
        hash_sequence = zero
    else:
        hash_sequence = double_sha256(b"".join(number(SEQUENCE, 4) for _ in inputs))
    if base == 0x01:
        hash_outputs = double_sha256(b"".join(outputs))
    elif base == 0x03 and index < len(outputs):
        hash_outputs = double_sha256(outputs[index])
    else:
        hash_outputs = zero
    txid, vout = inputs[index]
    script_code = b"\x19\x76\xa9\x14" + hash160(public_key) + b"\x88\xac"
    preimage = (
        number(VERSION, 4)
        + hash_prevouts
        + hash_sequence
        + txid
        + number(vout, 4)
        + script_code
        + number(amount, 8)
        + number(SEQUENCE, 4)
        + hash_outputs
        + number(LOCKTIME, 4)
        + number(sighash_type, 4)
    )
    return double_sha256(preimage)


if __name__ == "__main__":
    print("Test keys only. For learning; not safe for real funds.")
    print("Made-up coins: any node would reject this transaction, and it cannot spend anything real.")
    print("Guide: https://cryptonoobs.tech/knowledges/fees-and-the-mempool")
    print("Try it on the site: https://cryptonoobs.tech/practice/transaction")
    print()
    check_settings()
    fee, change = plan()
    sighash_type = SIGHASH_TYPES[SIGHASH]
    my_key = secp256k1.public_key(BIP143_TEST_KEY)

    inputs = [(made_up_coin(i), 0) for i in range(len(COIN_AMOUNTS))]
    pays = [(amount, recipient_key(i)) for i, amount in enumerate(PAY_AMOUNTS)]
    pays.append((change, my_key))
    outputs = [number(amount, 8) + with_length(locking_script(key)) for amount, key in pays]

    print("What you spend (made-up coins, all locked to the BIP143 test key):")
    for i, amount in enumerate(COIN_AMOUNTS):
        print(f"  Coin {i + 1}: {inputs[i][0][::-1].hex()}:0, {amount} sat, {test_address(my_key)}")
    print("Who you pay:")
    for i, (amount, key) in enumerate(pays[:-1]):
        print(f"  Output {i + 1}: {amount} sat to {test_address(key)}")
    print(f"  Change:   {change} sat back to {test_address(my_key)}")
    print(f"Fee: {sum(COIN_AMOUNTS)} - {sum(PAY_AMOUNTS) + change} = {fee} sat ({FEE_RATE} sat/vB on about {fee // FEE_RATE} vB)")
    print()

    witnesses = []
    for i, amount in enumerate(COIN_AMOUNTS):
        message = sighash(inputs, outputs, i, my_key, amount, sighash_type)
        r, s, flipped = sign(BIP143_TEST_KEY, message)
        if not verify(secp256k1.multiply(BIP143_TEST_KEY, secp256k1.G), message, r, s):
            stop("A signature did not check against its public key.")
        signature = der(r, s) + bytes([sighash_type])
        witnesses.append(count(2) + with_length(signature) + with_length(my_key))
        print(f"Coin {i + 1} signs {message.hex()} ({SIGHASH}), checked against the public key")

    parts = [("Version", number(VERSION, 4)), ("Marker and flag", b"\x00\x01"), ("Number of inputs", count(len(inputs)))]
    for i, (txid, vout) in enumerate(inputs):
        parts.append((f"Coin {i + 1}: previous txid", txid))
        parts.append((f"Coin {i + 1}: output number", number(vout, 4)))
        parts.append((f"Coin {i + 1}: scriptSig length", count(0)))
        parts.append((f"Coin {i + 1}: sequence", number(SEQUENCE, 4)))
    parts.append(("Number of outputs", count(len(outputs))))
    for i, output in enumerate(outputs):
        parts.append((f"Output {i + 1}: amount", output[:8]))
        parts.append((f"Output {i + 1}: locking script", output[8:]))
    for i, witness in enumerate(witnesses):
        parts.append((f"Witness {i + 1}", witness))
    parts.append(("Lock time", number(LOCKTIME, 4)))

    print()
    print("The bytes, part by part:")
    for name, data in parts:
        print(f"  {name:28} {data.hex()}")

    without_witness = (
        number(VERSION, 4) + count(len(inputs))
        + b"".join(txid + number(vout, 4) + count(0) + number(SEQUENCE, 4) for txid, vout in inputs)
        + count(len(outputs)) + b"".join(outputs) + number(LOCKTIME, 4)
    )
    everything = b"".join(data for name, data in parts)
    weight = len(without_witness) * 3 + len(everything)
    print()
    print(f"txid:   {double_sha256(without_witness)[::-1].hex()}")
    print(f"wtxid:  {double_sha256(everything)[::-1].hex()}")
    print(f"Size:   {len(everything)} bytes, {len(without_witness)} without the witness")
    print(f"Weight: {weight} weight units, {(weight + 3) // 4} vB")
    print()
    print(everything.hex())
    print()
    print("Valid in form. Any node would reject it because the coins are made up.")
