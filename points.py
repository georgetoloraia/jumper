import hashlib
import random

class ECPoint:
    def __init__(self, x, y, infinity=False):
        self.x = x
        self.y = y
        self.infinity = infinity  # Point at infinity (neutral element)

    def __str__(self):
        if self.infinity:
            return "Point at infinity"
        return f"({self.x}, {self.y})"


class Secp256k1:
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
        # Handle the identity element (point at infinity)
        if p1.infinity:
            return p2
        if p2.infinity:
            return p1

        # Handle the case where p1 and p2 are reflections of each other over the x-axis
        if p1.x == p2.x and p1.y != p2.y:
            return ECPoint(None, None, infinity=True)

        # Handle the case where p1 and p2 are the same point (point doubling)
        if p1.x == p2.x and p1.y == p2.y:
            if p1.y == 0:
                return ECPoint(None, None, infinity=True)  # Tangent is vertical
            lam = ((3 * p1.x**2 + Secp256k1.a) * pow(2 * p1.y, -1, Secp256k1.p)) % Secp256k1.p
        else:
            lam = ((p2.y - p1.y) * pow(p2.x - p1.x, -1, Secp256k1.p)) % Secp256k1.p

        x3 = (lam**2 - p1.x - p2.x) % Secp256k1.p
        y3 = (lam * (p1.x - x3) - p1.y) % Secp256k1.p
        return ECPoint(x3, y3)

    @staticmethod
    def scalar_mult(k, point):
        # Simple and insecure scalar multiplication, not using double-and-add
        result = ECPoint(None, None, infinity=True)  # Start with the point at infinity
        addend = point

        steps = []  # List to store the intermediate steps

        while k:
            if k & 1:
                result = Secp256k1.point_add(result, addend)
                steps.append(result)
            addend = Secp256k1.point_add(addend, addend)
            steps.append(addend)
            k >>= 1

        return result, steps

    @staticmethod
    def generate_public_key(private_key):
        public_key, steps = Secp256k1.scalar_mult(private_key, Secp256k1.G)
        return public_key, steps

    @staticmethod
    def hash_point(point):
        if point.infinity:
            raise ValueError("Cannot hash the point at infinity.")

        # Determine the prefix based on the y-coordinate
        prefix = b'\x02' if point.y % 2 == 0 else b'\x03'

        # Convert x-coordinate to bytes
        x_bytes = point.x.to_bytes(32, 'big')

        # Concatenate prefix and x-coordinate
        data = prefix + x_bytes

        # Step 1: SHA256 of compressed public key
        sha256_hash = hashlib.sha256(data).digest()

        # Step 2: RIPEMD160 of the SHA256 hash
        ripemd160_hash = hashlib.new('ripemd160', sha256_hash).hexdigest()
        return ripemd160_hash


# Example usage
target_hash = "739437bb3dd6d1983e66629c5f08c70e52769371"
while True:
    private_key = random.randint(73786976294838206464, 147573952589676412927)
    # private_key = random.randint(0, 2**256)
    # print(private_key)

    # Generate the public key
    public_key, steps = Secp256k1.generate_public_key(private_key)

    # Write the steps to a file and check for matching hash
    with open('steps.txt', 'a') as file:
        for i, step in enumerate(steps):
            # print(step)
            try:
                rmd = Secp256k1.hash_point(step)
                # print(f"Step {i + 1}: Hash = {rmd}")
                if rmd.startswith("739437bb"):
                    print(f"Matching Hash: {rmd}\nFrom: {private_key}")
                    if rmd == target_hash:
                        print(f"Matching step found at step {i + 1}!")
                        file.write(f"Step {i + 1}: {step}\n")
                        file.write(f"Matching Hash: {rmd}\nFrom: {private_key}")
                        break
            except ValueError as e:
                # Ignore the point at infinity
                continue
