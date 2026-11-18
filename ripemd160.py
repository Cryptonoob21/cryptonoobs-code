TEXT = "CryptoNoobs"

LEFT_WORDS = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
]

RIGHT_WORDS = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
]

LEFT_SHIFTS = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
]

RIGHT_SHIFTS = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
]

LEFT_CONSTANTS = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
RIGHT_CONSTANTS = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]


def rotate_left(value, count):
    value = value & 0xFFFFFFFF
    return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF


def mix(round_number, x, y, z):
    if round_number == 0:
        return x ^ y ^ z
    if round_number == 1:
        return (x & y) | (~x & z)
    if round_number == 2:
        return (x | ~y) ^ z
    if round_number == 3:
        return (x & z) | (y & ~z)
    return x ^ (y | ~z)


def pad(data):
    length_in_bits = len(data) * 8
    padded = data + b"\x80"
    while len(padded) % 64 != 56:
        padded = padded + b"\x00"
    padded = padded + (length_in_bits % 2**64).to_bytes(8, "little")
    return padded


def compress(state, block):
    words = []
    for i in range(16):
        words.append(int.from_bytes(block[i * 4:i * 4 + 4], "little"))

    a, b, c, d, e = state
    a2, b2, c2, d2, e2 = state

    for j in range(80):
        round_number = j // 16

        t = a + mix(round_number, b, c, d) + words[LEFT_WORDS[j]] + LEFT_CONSTANTS[round_number]
        t = (rotate_left(t, LEFT_SHIFTS[j]) + e) & 0xFFFFFFFF
        a = e
        e = d
        d = rotate_left(c, 10)
        c = b
        b = t

        t = a2 + mix(4 - round_number, b2, c2, d2) + words[RIGHT_WORDS[j]] + RIGHT_CONSTANTS[round_number]
        t = (rotate_left(t, RIGHT_SHIFTS[j]) + e2) & 0xFFFFFFFF
        a2 = e2
        e2 = d2
        d2 = rotate_left(c2, 10)
        c2 = b2
        b2 = t

    new_state = [
        (state[1] + c + d2) & 0xFFFFFFFF,
        (state[2] + d + e2) & 0xFFFFFFFF,
        (state[3] + e + a2) & 0xFFFFFFFF,
        (state[4] + a + b2) & 0xFFFFFFFF,
        (state[0] + b + c2) & 0xFFFFFFFF,
    ]
    return new_state


def ripemd160(data: bytes) -> bytes:
    state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    padded = pad(data)
    for start in range(0, len(padded), 64):
        state = compress(state, padded[start:start + 64])
    result = b""
    for value in state:
        result = result + value.to_bytes(4, "little")
    return result


if __name__ == "__main__":
    print("For learning only, not financial advice.")
    print("Guide: https://cryptonoobs.tech/knowledges/what-is-a-hash")
    print("Try it in your browser: https://cryptonoobs.tech/practice/hash")
    print(f"Text:       {TEXT}")
    print(f"RIPEMD-160: {ripemd160(TEXT.encode()).hex()}")
