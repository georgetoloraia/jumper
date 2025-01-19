import random
import hashlib

class ECPoint:
    def __init__(self, x, y, infinity=False):
        self.x = x
        self.y = y
        self.infinity = infinity

    def __str__(self):
        if self.infinity:
            return "Point at infinity"
        return f"({self.x}, {self.y})"

class Secp256k1:
    # Elliptic curve parameters
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    a = 0
    b = 7
    G = ECPoint(
        x=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        y=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    )
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    h = 1

    @staticmethod
    def point_add(p1, p2):
        # Elliptic curve point addition
        if p1.infinity:
            return p2
        if p2.infinity:
            return p1
        if p1.x == p2.x and p1.y != p2.y:
            return ECPoint(None, None, infinity=True)
        if p1.x == p2.x and p1.y == p2.y:
            if p1.y == 0:
                return ECPoint(None, None, infinity=True)
            lam = ((3 * p1.x**2 + Secp256k1.a) * pow(2 * p1.y, -1, Secp256k1.p)) % Secp256k1.p
        else:
            lam = ((p2.y - p1.y) * pow(p2.x - p1.x, -1, Secp256k1.p)) % Secp256k1.p
        x3 = (lam**2 - p1.x - p2.x) % Secp256k1.p
        y3 = (lam * (p1.x - x3) - p1.y) % Secp256k1.p
        return ECPoint(x3, y3)

    @staticmethod
    def hash_point(point):
        # Hash the elliptic curve point
        if point.infinity:
            raise ValueError("Cannot hash the point at infinity.")
        prefix = b'\x02' if point.y % 2 == 0 else b'\x03'
        x_bytes = point.x.to_bytes(32, 'big')
        data = prefix + x_bytes
        sha256_hash = hashlib.sha256(data).digest()
        ripemd160_hash = hashlib.new('ripemd160', sha256_hash).hexdigest()
        return ripemd160_hash

def test_random_binary_sequences():
    target_prefix = "739437bb3dd"  # The target hash prefix
    start_point = Secp256k1.G  # Generator point
    max_length = 67  # Maximum binary sequence length
    max_attempts = 1000000000000000000000  # Maximum number of random attempts

    with open('steps.txt', 'a') as file:
        for _ in range(max_attempts):
            # Generate a random binary sequence starting with '1'
            binary = '1' + bin(random.getrandbits(max_length - 1))[2:].zfill(max_length - 1)
            result = ECPoint(None, None, infinity=True)  # Start with point at infinity
            addend = start_point

            # print(f"Attempt {attempt + 1}: Testing sequence: {binary}")  # Debug output
            for bit in binary:
                if bit == "1":
                    result = Secp256k1.point_add(result, addend)
                    rmd = Secp256k1.hash_point(result)
                    if rmd.startswith(target_prefix):
                        print(f"Matching Hash Found: {rmd}\nPoint: {result}\nSequence: {binary}")
                        file.write(f"Matching Hash Found: {rmd}\nPoint: {result}\nSequence: {binary}")

                addend = Secp256k1.point_add(addend, addend)

                rmd = Secp256k1.hash_point(addend)
                if rmd.startswith(target_prefix):
                    print(f"Matching Hash Found: {rmd}\nPoint: {addend}\nSequence: {binary}")
                    file.write(f"Matching Hash Found: {rmd}\nPoint: {result}\nSequence: {binary}")
                

    print("No match found after maximum attempts.")


# Run the randomized test
test_random_binary_sequences()




