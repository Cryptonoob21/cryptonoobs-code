PRIVATE_KEY = 1

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        slope = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        slope = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (slope * slope - a[0] - b[0]) % P
    y = (slope * (a[0] - x) - a[1]) % P
    return (x, y)


def multiply(k, point):
    result = None
    while k > 0:
        if k % 2 == 1:
            result = add(result, point)
        point = add(point, point)
        k = k // 2
    return result


def compress(point):
    if point[1] % 2 == 0:
        first = b"\x02"
    else:
        first = b"\x03"
    return first + point[0].to_bytes(32, "big")


def public_key(private_key):
    if private_key < 1 or private_key >= N:
        raise ValueError("A private key must be from 1 to N - 1")
    return compress(multiply(private_key, G))


def point_from_x(x):
    y_squared = (pow(x, 3, P) + 7) % P
    y = pow(y_squared, (P + 1) // 4, P)
    if y * y % P != y_squared:
        raise ValueError("This x is not on the curve")
    if y % 2 == 1:
        y = P - y
    return (x, y)


if __name__ == "__main__":
    print("Test keys only. For learning; not safe for real funds.")
    print("Guide: https://cryptonoobs.tech/knowledges/from-12-words-to-a-bitcoin-address")
    print(f"Private key: {PRIVATE_KEY}")
    print(f"Public key:  {public_key(PRIVATE_KEY).hex()}")
