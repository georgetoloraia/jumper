import sec
import random

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
pub = 0x678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb6

gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

tes = "04cd10ce592a9c4918948a5b4e92e9702e6c36eed1a627594f67066792b3a227cedba7be9df6e8117bee0499e243e4df90e13efdd8e14e1778e2247c0e16661057"

zina = random.randint(0, 2**256)

def load_public_keys(filename):
    """
    Load public keys from a file into a set.

    Args:
    - filename (str): The file containing public keys, one per line.

    Returns:
    - A set of public keys (str) from the file.
    """
    try:
        with open(filename, "r") as file:
            public_keys = {line.strip() for line in file}
        return public_keys
    except FileNotFoundError:
        print(f"Error: File {filename} not found.")
        return set()

# Load public keys once
public_keys = load_public_keys("pubs.txt")

import requests

# Telegram bot configuration
BOT_TOKEN = "6526185567:AAHt8a2409V36PAwaL9y4uPw2YZC1ytrFyo"
CHAT_ID = "7037604847"

def send_telegram_message(message):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {"chat_id": CHAT_ID, "text": message}
    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            print("Telegram message sent successfully!")
        else:
            print(f"Failed to send Telegram message. Status: {response.status_code}")
    except Exception as e:
        print(f"Error sending Telegram message: {e}")


# Start simulation
selapa = n - zina % n  # Initial value
print(selapa)
counter = 0

while True:
    try:
        # Generate public key using the private key `selapa`
        point = sec.Secp256k1.generate_public_key(selapa)
        # with open("keys.txt", "a") as file:
        #     file.write(f"{selapa}\n")

        x, y = point.x, point.y  # Access x and y coordinates directly
        # print(f"Generated Public Key: x={hex(x)}, y={hex(y)}")
        # print(x)
        public = f"04{hex(x)[2:]}{hex(y)[2:]}"
        # Check if the generated public key matches the target
        if public in public_keys:
            with open("KEY--FOUND!!!.txt", "a") as file:
                file.write(f"Private Key: {hex(selapa)}\n")
            print(f"Match found! Private Key: {hex(selapa)}")

            # Send Telegram message
            send_telegram_message(f"Match found! Private Key: {hex(selapa)}")


        # Increment the private key for the next iteration
        if counter % 2 == 0:
            selapa = (selapa - gx) % n  # Subtract for even counters
        else:
            selapa = (selapa - gy) % n  # Add for odd counters
            # print(selapa)
        counter += 1

        # Log progress every 1000 iterations
        # if counter % 10000 == 0:
        #     print(f"Checked {counter} private keys...\n{public}")
    except KeyboardInterrupt:
        print("Simulation interrupted by user.")
        break
    except Exception as e:
        print(f"Error: {e}")
        break
