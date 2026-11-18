CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32 = 1
BECH32M = 0x2BC830A3


def polymod(values):
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    check = 1
    for value in values:
        top = check >> 25
        check = (check & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            if (top >> i) & 1:
                check = check ^ generator[i]
    return check


def expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def encode(hrp, data, constant):
    number = polymod(expand(hrp) + data + [0, 0, 0, 0, 0, 0]) ^ constant
    check = [(number >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(CHARSET[d] for d in data + check)


def decode(text):
    if len(text) > 90 or any(ord(c) < 33 or ord(c) > 126 for c in text):
        return None
    if text.lower() != text and text.upper() != text:
        return None
    text = text.lower()
    position = text.rfind("1")
    if position < 1 or position + 7 > len(text):
        return None
    if any(c not in CHARSET for c in text[position + 1:]):
        return None
    hrp = text[:position]
    data = [CHARSET.find(c) for c in text[position + 1:]]
    constant = polymod(expand(hrp) + data)
    if constant != BECH32 and constant != BECH32M:
        return None
    return hrp, data[:-6], constant


def regroup(data, from_bits, to_bits, pad):
    value = 0
    bits = 0
    result = []
    for item in data:
        value = (value << from_bits) | item
        bits = bits + from_bits
        while bits >= to_bits:
            bits = bits - to_bits
            result.append((value >> bits) & ((1 << to_bits) - 1))
    if pad and bits > 0:
        result.append((value << (to_bits - bits)) & ((1 << to_bits) - 1))
    if not pad and (bits >= from_bits or (value << (to_bits - bits)) & ((1 << to_bits) - 1)):
        return None
    return result


def segwit_address(hrp, version, program):
    if version == 0:
        constant = BECH32
    else:
        constant = BECH32M
    return encode(hrp, [version] + regroup(program, 8, 5, True), constant)


def read_segwit_address(hrp, address):
    decoded = decode(address)
    if decoded is None or decoded[0] != hrp or len(decoded[1]) < 1:
        return None
    version = decoded[1][0]
    if version > 16:
        return None
    if version == 0 and decoded[2] != BECH32:
        return None
    if version > 0 and decoded[2] != BECH32M:
        return None
    program = regroup(decoded[1][1:], 5, 8, False)
    if program is None or len(program) < 2 or len(program) > 40:
        return None
    if version == 0 and len(program) != 20 and len(program) != 32:
        return None
    return version, bytes(program)
