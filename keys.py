WORDS = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
NEW_WORDS = False
NEW_WORD_COUNT = 12
ADDRESSES = 3
SHOW_PRIVATE_KEYS = False

import hashlib
import hmac
import secrets

import base58
import bech32
import secp256k1
from ripemd160 import ripemd160

EXAMPLE = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
HARDENED = 0x80000000


def read_word_list():
    with open("english.txt") as file:
        return file.read().split()


def sha256(data):
    return hashlib.sha256(data).digest()


def hash160(data):
    return ripemd160(sha256(data))


def bits_of(data):
    text = ""
    for byte in data:
        text = text + format(byte, "08b")
    return text


def words_from_entropy(entropy, word_list):
    bits = bits_of(entropy)
    checksum = bits_of(sha256(entropy))[: len(entropy) // 4]
    all_bits = bits + checksum
    words = []
    for i in range(0, len(all_bits), 11):
        words.append(word_list[int(all_bits[i:i + 11], 2)])
    return words, checksum


def entropy_from_words(words, word_list):
    bits = ""
    for word in words:
        if word not in word_list:
            raise ValueError("Unknown word: " + word)
        bits = bits + format(word_list.index(word), "011b")
    checksum_size = len(bits) // 33
    entropy_bits = bits[: len(bits) - checksum_size]
    entropy = int(entropy_bits, 2).to_bytes(len(entropy_bits) // 8, "big")
    if words_from_entropy(entropy, word_list)[1] != bits[len(bits) - checksum_size:]:
        raise ValueError("The checksum does not match: a word is wrong")
    return entropy


def seed_from_words(words):
    return hashlib.pbkdf2_hmac("sha512", " ".join(words).encode(), b"mnemonic", 2048)


def master_key(seed):
    result = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return int.from_bytes(result[:32], "big"), result[32:]


def child_key(private_key, chain_code, index):
    if index >= HARDENED:
        data = b"\x00" + private_key.to_bytes(32, "big") + index.to_bytes(4, "big")
    else:
        data = secp256k1.public_key(private_key) + index.to_bytes(4, "big")
    result = hmac.new(chain_code, data, hashlib.sha512).digest()
    left = int.from_bytes(result[:32], "big")
    child = (left + private_key) % secp256k1.N
    if left >= secp256k1.N or child == 0:
        raise ValueError("Invalid child key, use the next index")
    return child, result[32:]


def read_path(path):
    numbers = []
    for part in path.split("/")[1:]:
        if part.endswith("'"):
            numbers.append(int(part[:-1]) + HARDENED)
        else:
            numbers.append(int(part))
    return numbers


def key_at(seed, path):
    private_key, chain_code = master_key(seed)
    for index in read_path(path):
        private_key, chain_code = child_key(private_key, chain_code, index)
    return private_key


def wif(private_key, network):
    if network == "main":
        version = b"\x80"
    else:
        version = b"\xef"
    return base58.encode_check(version + private_key.to_bytes(32, "big") + b"\x01")


def tagged_hash(tag, data):
    tag_hash = sha256(tag.encode())
    return sha256(tag_hash + tag_hash + data)


def taproot_output_key(public_key):
    internal = secp256k1.point_from_x(int.from_bytes(public_key[1:], "big"))
    tweak = int.from_bytes(tagged_hash("TapTweak", public_key[1:]), "big")
    output = secp256k1.add(internal, secp256k1.multiply(tweak, secp256k1.G))
    return output[0].to_bytes(32, "big")


def address(kind, public_key, network):
    if network == "main":
        legacy_version, script_version, hrp = b"\x00", b"\x05", "bc"
    else:
        legacy_version, script_version, hrp = b"\x6f", b"\xc4", "tb"
    if kind == "Legacy":
        return base58.encode_check(legacy_version + hash160(public_key))
    if kind == "Nested SegWit":
        script = b"\x00\x14" + hash160(public_key)
        return base58.encode_check(script_version + hash160(script))
    if kind == "Native SegWit":
        return bech32.segwit_address(hrp, 0, hash160(public_key))
    return bech32.segwit_address(hrp, 1, taproot_output_key(public_key))


PURPOSES = {"Legacy": 44, "Nested SegWit": 49, "Native SegWit": 84, "Taproot": 86}

print("Test keys only. For learning; not safe for real funds.")
print("Never put real words here. Guide: https://cryptonoobs.tech/knowledges/from-12-words-to-a-bitcoin-address")
print("Try it in your browser: https://cryptonoobs.tech/practice/keys")
print()

word_list = read_word_list()
if NEW_WORDS:
    entropy = secrets.token_bytes(NEW_WORD_COUNT * 4 // 3)
    words, checksum = words_from_entropy(entropy, word_list)
else:
    words = WORDS.split()
    entropy = entropy_from_words(words, word_list)
    checksum = words_from_entropy(entropy, word_list)[1]

if " ".join(words) == EXAMPLE:
    networks = ["main", "test"]
    print("These are the public example words: everyone knows them, so coins sent to them are taken by others.")
else:
    networks = ["test"]
    print("Only the public example gets main network addresses here. These words get test format only.")
print()

seed = seed_from_words(words)
master, chain_code = master_key(seed)
print(f"Random bits:  {entropy.hex()} ({len(entropy) * 8} bits)")
print(f"Checksum:     {checksum}")
print(f"Words:        {' '.join(words)}")
print(f"Seed:         {seed.hex()}")
if SHOW_PRIVATE_KEYS:
    print(f"Master key:   {master.to_bytes(32, 'big').hex()}")
else:
    print("Master key:   hidden (set SHOW_PRIVATE_KEYS = True)")
print(f"Chain code:   {chain_code.hex()}")

for network in networks:
    if network == "main":
        coin = 0
    else:
        coin = 1
    for kind in PURPOSES:
        print()
        print(f"{kind}, {network} network")
        for index in range(ADDRESSES):
            path = f"m/{PURPOSES[kind]}'/{coin}'/0'/0/{index}"
            private_key = key_at(seed, path)
            public_key = secp256k1.public_key(private_key)
            if index == 0:
                print(f"  Public key:  {public_key.hex()}")
                if SHOW_PRIVATE_KEYS:
                    print(f"  Private key: {private_key.to_bytes(32, 'big').hex()}")
                    print(f"  WIF:         {wif(private_key, network)}")
            print(f"  {path}  {address(kind, public_key, network)}")
