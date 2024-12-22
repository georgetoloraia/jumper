# jumper

```py
target_hash = "739437bb3dd6d1983e66629c5f08c70e52769371"
# priv_min = random.randint(73786976294838206464, 147573952589676412927)
# for kee in range(99896976294838206464, 147573952589676412927):
while True:
    private_key = random.randint(73786976294838206464, 92233720368547758080)
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
                if rmd.startswith("739437b"):
                    print(f"Matching Hash: {rmd}\nFrom: {private_key}")
                    # Send Telegram message
                    send_telegram_message(f"Match found! Private Key: {f"From: {private_key}\n{rmd}"}")
                    if rmd == target_hash:
                        print(f"Matching step found at step {i + 1}!")
                        file.write(f"Step {i + 1}: {step}\n")
                        file.write(f"Matching Hash: {rmd}\nFrom: {private_key}")
                        break
            except ValueError as e:
                # Ignore the point at infinity
                continue
```