MESSAGE_HASH = "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"

import hashlib
import hmac

from secp256k1 import G, N, add, multiply, public_key

BIP143_TEST_KEY = 0x619C335025C7F4012E556C2A58B2506E30B8511B53ADE95EA316FD8C3286FEB9
BIP143_SIGNATURE = "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee"


def hmac_sha256(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()


def nonce(private_key, message_hash):
    x = private_key.to_bytes(32, "big")
    h = (int.from_bytes(message_hash, "big") % N).to_bytes(32, "big")
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac_sha256(k, v + b"\x00" + x + h)
    v = hmac_sha256(k, v)
    k = hmac_sha256(k, v + b"\x01" + x + h)
    v = hmac_sha256(k, v)
    while True:
        v = hmac_sha256(k, v)
        candidate = int.from_bytes(v, "big")
        if candidate >= 1 and candidate < N:
            return candidate
        k = hmac_sha256(k, v + b"\x00")
        v = hmac_sha256(k, v)


def sign(private_key, message_hash):
    if len(message_hash) != 32:
        raise ValueError("The message hash must be 32 bytes")
    z = int.from_bytes(message_hash, "big")
    k = nonce(private_key, message_hash)
    r = multiply(k, G)[0] % N
    s = pow(k, -1, N) * (z + r * private_key) % N
    if r == 0 or s == 0:
        raise ValueError("Bad signature, try another message")
    flipped = False
    if s > N // 2:
        s = N - s
        flipped = True
    return r, s, flipped


def der_number(number):
    data = number.to_bytes(32, "big").lstrip(b"\x00")
    if len(data) == 0:
        data = b"\x00"
    if data[0] >= 0x80:
        data = b"\x00" + data
    return b"\x02" + bytes([len(data)]) + data


def der(r, s):
    body = der_number(r) + der_number(s)
    return b"\x30" + bytes([len(body)]) + body


def verify(public_point, message_hash, r, s):
    if r < 1 or r >= N or s < 1 or s >= N:
        return False
    z = int.from_bytes(message_hash, "big")
    w = pow(s, -1, N)
    point = add(multiply(z * w % N, G), multiply(r * w % N, public_point))
    return point is not None and point[0] % N == r


if __name__ == "__main__":
    print("Test keys only. For learning; not safe for real funds.")
    print("Try it on the site: https://cryptonoobs.tech/practice/transaction")
    message_hash = bytes.fromhex(MESSAGE_HASH)
    print(f"Message hash:  {message_hash.hex()}")
    print("Test key:      the public example key from BIP143, known to everyone")
    print(f"Public key:    {public_key(BIP143_TEST_KEY).hex()}")
    r, s, flipped = sign(BIP143_TEST_KEY, message_hash)
    print(f"r:             {r:064x}")
    print(f"s:             {s:064x}")
    if flipped:
        print("Low S:         s was in the upper half, so it was replaced by N - s")
    else:
        print("Low S:         s was already in the lower half")
    signature = der(r, s)
    print(f"DER ({len(signature)} bytes): {signature.hex()}")
    print(f"Signature checks against the public key: {verify(multiply(BIP143_TEST_KEY, G), message_hash, r, s)}")
    if MESSAGE_HASH == "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670":
        print(f"Same as the signature printed in BIP143: {signature.hex() == BIP143_SIGNATURE}")
