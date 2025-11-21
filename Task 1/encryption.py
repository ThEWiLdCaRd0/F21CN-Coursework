import json

def text_to_bits(text):
    bits = []
    for char in text:
        binval = bin(ord(char))[2:].zfill(8)
        bits.extend([int(bit) for bit in binval])
    return bits

def split_bits(bits, n):
    # Split bitlist into n-sized blocks, padding last
    return [bits[i:i + n] + [0] * (n - len(bits[i:i + n])) if len(bits[i:i + n]) < n else bits[i:i + n]
            for i in range(0, len(bits), n)]

def encrypt_block(block_bits, public_key):
    return sum([bit * h for bit, h in zip(block_bits, public_key)])

if __name__ == "__main__":
    # Load public key and block size from public_key.json
    with open('public_key.json', 'r') as f:
        key_data = json.load(f)
    
    public_key = key_data['public_key']
    n = key_data['block_size']
    
    print(f"Loaded public key (length {len(public_key)})")
    print(f"Block size: {n}")
    
    # Get plaintext from user
    plaintext = input("\nEnter plaintext to encrypt: ")
    plaintext_bits = text_to_bits(plaintext)
    blocks = split_bits(plaintext_bits, n)

    # Encrypt each block
    ciphertexts = [encrypt_block(block, public_key) for block in blocks]
    print("\nCiphertexts (send these):")
    for i, c in enumerate(ciphertexts):
        print(f"Block {i + 1}: {c}")
    print("\nBlock size n:", n)
    print("Number of blocks:", len(ciphertexts))
    
    # Export public key and ciphertext to new JSON file
    output_data = {
        'public_key': public_key,
        'block_size': n,
        'ciphertexts': ciphertexts
    }
    with open('encrypted_message.json', 'w') as f:
        json.dump(output_data, f)
    print("\nPublic key and ciphertext exported to encrypted_message.json.")
