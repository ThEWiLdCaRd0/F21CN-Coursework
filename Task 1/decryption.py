import json

def modinv(a, m):
    def egcd(a, b):
        if a == 0: return b, 0, 1
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError('Modular inverse does not exist')
    return x % m

def solve_superinc_knapsack(c_prime, e):
    result = []
    for si in reversed(e):
        bit = int(c_prime >= si)
        result.insert(0, bit)
        if bit:
            c_prime -= si
    return result

def bits_to_text(bits):
    chars, n = [], 8
    for i in range(0, len(bits), n):
        byte_bits = bits[i:i + n]
        if len(byte_bits) < n:
            byte_bits += [0] * (n - len(byte_bits))
        char = chr(int(''.join(str(b) for b in byte_bits), 2))
        chars.append(char)
    return ''.join(chars)

if __name__ == "__main__":
    # Load private key from private_key.json
    with open('recepient_private_key.json', 'r') as f:
        private_data = json.load(f)
    
    e = private_data['private_key']['e']
    q = private_data['private_key']['q']
    w = private_data['private_key']['w']
    n = private_data['block_size']
    
    print(f"Loaded private key:")
    print(f"  e: {e}")
    print(f"  q: {q}")
    print(f"  w: {w}")
    print(f"  Block size: {n}")
    
    # Load ciphertexts from encrypted_message.json
    with open('encrypted_message.json', 'r') as f:
        encrypted_data = json.load(f)
    
    ciphertexts = encrypted_data['ciphertexts']
    print(f"\nLoaded {len(ciphertexts)} ciphertext blocks")
    
    # Decrypt
    w_inv = modinv(w, q)
    recovered_bits = []
    for c in ciphertexts:
        c_prime = (c * w_inv) % q
        bits = solve_superinc_knapsack(c_prime, e)
        recovered_bits.extend(bits)

    recovered_text = bits_to_text(recovered_bits)
    print("\n--- Decrypted Plaintext ---")
    print(recovered_text)
