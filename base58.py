import hashlib

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def encode(data):
    number = int.from_bytes(data, "big")
    text = ""
    while number > 0:
        number, remainder = divmod(number, 58)
        text = ALPHABET[remainder] + text
    for byte in data:
        if byte != 0:
            break
        text = "1" + text
    return text


def decode(text):
    number = 0
    for character in text:
        number = number * 58 + ALPHABET.index(character)
    data = b""
    while number > 0:
        data = bytes([number % 256]) + data
        number = number // 256
    for character in text:
        if character != "1":
            break
        data = b"\x00" + data
    return data


def checksum(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]


def encode_check(data):
    return encode(data + checksum(data))


def decode_check(text):
    data = decode(text)
    if len(data) < 5 or checksum(data[:-4]) != data[-4:]:
        return None
    return data[:-4]
