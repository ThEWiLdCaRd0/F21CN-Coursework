import random
import sympy
import json


def generate_superincreasing_sequence(n, start=10, stop=50):  # Increased range
    sequence = []
    total = 0
    for _ in range(n):
        next_val = random.randint(total + start, total + stop)
        sequence.append(next_val)
        total += next_val
    return sequence


def generate_keypair(n):
    e = generate_superincreasing_sequence(n)
    min_q = 2 * e[-1] + 1
    q = sympy.nextprime(min_q)
    while True:
        w = random.randint(2, q - 1)
        if sympy.gcd(w, q) == 1:
            break
    h = [(w * ei) % q for ei in e]
    return {'public': h, 'private': {'e': e, 'q': q, 'w': w}, 'n': n}


if __name__ == "__main__":
    n = int(input("Enter bit-length for encryption blocks (n): "))
    keypair = generate_keypair(n)
    print("\n--- Public Key (share with sender) ---")
    print(keypair['public'])
    print("\n--- Private Key (keep safe!) ---")
    print("e (superincreasing):", keypair['private']['e'])
    print("q:", keypair['private']['q'])
    print("w:", keypair['private']['w'])
    print("n:", n)

    # Save public key and block size for Alice
    public_data = {
        'public_key': keypair['public'],
        'block_size': n
    }
    # Public key to be shared with Alice/anyone = Bob's public key
    with open('public_key.json', 'w') as f:
        json.dump(public_data, f)
    print("\nRecipient's public key and block size exported to public_key.json.")

    # Save all private details for Bob
    private_data = {
        'public_key': keypair['public'],        
        'private_key': {
            'e': keypair['private']['e'],
            'q': keypair['private']['q'],
            'w': keypair['private']['w']
        },
        'block_size': n
    }
    # Private key not to be shared with Alice/anyone = Bob's private key
    with open('recepient_private_key.json', 'w') as f:
        json.dump(private_data, f)
    print("Full private key details exported to recepient_private_key.json.")
