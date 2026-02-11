import hashlib
import os
import binascii
import time

# -----------------------------
# Helper functions
# -----------------------------

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def salted_sha256_hex(password: str, salt_bytes: bytes) -> str:
    return hashlib.sha256(salt_bytes + password.encode("utf-8")).hexdigest()

def pbkdf2_hex(password: str, salt_bytes: bytes, iterations: int = 200_000) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, iterations)
    return binascii.hexlify(dk).decode("utf-8")

# -----------------------------
# Provided "user database"
# (These are SAFE training hashes)
# -----------------------------
# Format:
# username : (scheme, salt_hex, hash_hex)
users = {
    "alice": ("sha256", None, "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"),  # password
    "bob": ("salted_sha256", "a1b2c3d4e5f60708", None),
    "carol": ("pbkdf2", "00112233445566778899aabbccddeeff", None),
}

# We'll generate bob & carol hashes for a known training password list
training_passwords = [
    "123456", "qwerty", "letmein", "football", "iloveyou",
    "Password1!", "Spring2026!", "correcthorsebatterystaple",
    "dragon", "monkey", "shadow", "admin", "welcome"
]

def print_user_database():
    print()
    print("=== Stored Password Database (Training View) ===")

    for username, (scheme, salt_hex, hash_hex) in users.items():
        print(f"User: {username}")
        print(f"  Scheme: {scheme}")

        if salt_hex:
            print(f"  Salt: {salt_hex}")

        print(f"  Stored hash: {hash_hex}")
        print()

def print_dictionary_hashes():
    print()
    print("=== Dictionary Password Hashes (Attacker Precomputation) ===")
    print("These hashes are computed BEFORE cracking begins.\n")

    # Salts used
    bob_salt = bytes.fromhex(users["bob"][1])
    carol_salt = bytes.fromhex(users["carol"][1])

    for pw in training_passwords:
        print(f"Password guess: '{pw}'")

        h1 = sha256_hex(pw)
        print(f"  SHA-256 (no salt): {h1}")

        h2 = salted_sha256_hex(pw, bob_salt)
        print(f"  SHA-256 + Bob's salt: {h2}")

        h3 = pbkdf2_hex(pw, carol_salt, iterations=200_000)
        print(f"  PBKDF2 (200k iters): {h3}")

        print("-" * 60)


def get_user_salt(prompt_text: str, default_hex: str) -> bytes:
    print()
    print(prompt_text)
    print(f"Enter salt as HEX (even number of hex chars). Example: {default_hex}")
    user_in = input(f"Salt hex [press Enter for default {default_hex}]: ").strip()

    if user_in == "":
        user_in = default_hex

    # Remove spaces if a student types "aa bb cc"
    user_in = user_in.replace(" ", "")

    # Basic validation
    if len(user_in) % 2 != 0:
        raise ValueError("Salt hex must have an even number of characters (each byte = 2 hex chars).")

    try:
        return bytes.fromhex(user_in)
    except ValueError:
        raise ValueError("Salt must be valid hex characters (0-9, a-f).")


def build_training_hashes():
    # Set bob and carol to be crackable from training_passwords
    bob_real_pw = "Spring2026!"
    carol_real_pw = "correcthorsebatterystaple"
    alice_real_pw = "Password1!"

    # Ask the user for Bob's salt to demonstrate salt changes the resulting hash.
    # (We keep Carol fixed so PBKDF2 timing comparisons stay consistent.)
    default_bob_salt_hex = users["bob"][1]  # existing default in users dict
    bob_salt_bytes = get_user_salt(
        "Bob uses SALTED SHA-256. Try entering different salts to see Bob's stored hash change.",
        default_bob_salt_hex
    )

    # Update the salt stored for Bob to whatever the user entered
    users["bob"] = ("salted_sha256", bob_salt_bytes.hex(), salted_sha256_hex(bob_real_pw, bob_salt_bytes))

    # Carol stays fixed (PBKDF2) for consistency
    carol_salt = bytes.fromhex(users["carol"][1])
    carol_hash = pbkdf2_hex(carol_real_pw, carol_salt, iterations=200_000)
    users["carol"] = ("pbkdf2", users["carol"][1], carol_hash)
    users["alice"] = ("sha256", None, sha256_hex(alice_real_pw))

def crack_users():
    print("=== Training Password Cracker (Verbose Mode) ===")
    print(f"Candidates: {len(training_passwords)} passwords")
    print()

    for username, (scheme, salt_hex, target_hash) in users.items():
        print(f"User: {username}")
        print(f"  Scheme: {scheme}")

        if salt_hex:
            print(f"  Salt: {salt_hex}")

        print(f"  Stored hash: {target_hash}")
        print("  Attempting guesses...")

        start = time.time()
        found = None

        for guess in training_passwords:
            if scheme == "sha256":
                attempted_hash = sha256_hex(guess)

            elif scheme == "salted_sha256":
                salt = bytes.fromhex(salt_hex)
                attempted_hash = salted_sha256_hex(guess, salt)

            elif scheme == "pbkdf2":
                salt = bytes.fromhex(salt_hex)
                attempted_hash = pbkdf2_hex(guess, salt, iterations=200_000)

            else:
                raise ValueError("Unknown scheme")

            print(f"    Guess: '{guess}'")
            print(f"      Hash: {attempted_hash}")

            if attempted_hash == target_hash:
                found = guess
                print("      >>> MATCH FOUND <<<")
                break

        elapsed_ms = (time.time() - start) * 1000

        print(f"  Cracked?: {'YES' if found else 'NO'}")
        if found:
            print(f"  Password: {found}")
        print(f"  Time: {elapsed_ms:.2f} ms")


if __name__ == "__main__":
    build_training_hashes()
    print_dictionary_hashes()
    crack_users()
