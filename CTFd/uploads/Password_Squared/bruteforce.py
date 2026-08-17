import hashlib
import itertools

TARGET = "target.enc"

# Something about the password is wrong here.
# Fix the search space.

CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" #hmmmm
MAX_LENGTH = 8


def generate_candidates():
    for length in range(1, MAX_LENGTH + 1):
        for chars in itertools.product(CHARSET, repeat=length):
            yield "".join(chars)


def check(password):
    with open(TARGET, "rb") as f:
        data = f.read()

    if data[:4] != b"SP2\x01":
        return False

    salt = data[4:20]
    nonce = data[20:36]
    ciphertext = data[36:]

    stream = b""
    counter = 0

    while len(stream) < len(ciphertext):
        block = hashlib.sha256(
            salt
            + nonce
            + password.encode()
            + counter.to_bytes(4, "big")
        ).digest()

        stream += block
        counter += 1

    plaintext = bytes(
        a ^ b
        for a, b in zip(ciphertext, stream[:len(ciphertext)])
    )

    if plaintext.startswith(b"The password to get into"):
        print("\nPassword found:", password)
        print("\n" + plaintext.decode())
        return True

    return False


for candidate in generate_candidates():
    if check(candidate):
        break