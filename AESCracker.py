#!/usr/bin/env python3
import numpy as np
import argparse
import sys
from termcolor import colored
from time import sleep
import time
import random
import os

class KeyRecoveryError(Exception):
    """Raised when key recovery fails."""

def clear_screen():
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

# AES S-Box
S_BOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
]

INVERSE_S_BOX = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
]

def galois_multiply(a, b):
    """Galois Field multiplication for AES MixColumns."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        carry = a & 0x80
        a <<= 1
        a &= 0xFF
        if carry:
            a ^= 0x1B
        b >>= 1
    return p

def sub_bytes(state):
    """SubBytes transformation."""
    for i in range(4):
        for j in range(4):
            state[i][j] = S_BOX[state[i][j]]
    return state

def shift_rows(state):
    """ShiftRows transformation."""
    state[1] = np.roll(state[1], -1)
    state[2] = np.roll(state[2], -2)
    state[3] = np.roll(state[3], -3)
    return state

def mix_columns(state):
    """MixColumns transformation."""
    for i in range(4):
        col = state[:, i]
        state[:, i] = [
            galois_multiply(0x02, col[0]) ^ galois_multiply(0x03, col[1]) ^ col[2] ^ col[3],
            col[0] ^ galois_multiply(0x02, col[1]) ^ galois_multiply(0x03, col[2]) ^ col[3],
            col[0] ^ col[1] ^ galois_multiply(0x02, col[2]) ^ galois_multiply(0x03, col[3]),
            galois_multiply(0x03, col[0]) ^ col[1] ^ col[2] ^ galois_multiply(0x02, col[3])
        ]
    return state

def add_round_key(state, round_key):
    """AddRoundKey transformation."""
    return np.bitwise_xor(state, round_key)

def convert_to_matrix(data):
    """Convert 16-byte data into a 4x4 matrix."""
    return np.array([[data[i + 4 * j] for i in range(4)] for j in range(4)], dtype=np.uint8)

def matrix_to_bytes(matrix):
    """Convert a 4x4 matrix into 16-byte data."""
    return bytes(matrix.flatten(order='F'))

def pad_data(data, block_size=16):
    """Pad data using PKCS7 padding."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def unpad_data(data):
    """Remove PKCS7 padding."""
    pad_len = data[-1]
    return data[:-pad_len]

def encrypt_aes(plaintext, key):
    """Encrypt plaintext using AES-128."""
    if len(plaintext) % 16 != 0:
        plaintext = pad_data(plaintext)
    
    state = convert_to_matrix(plaintext)
    round_key = convert_to_matrix(key)
    
    # Initial round
    state = add_round_key(state, round_key)
    
    # 9 main rounds
    for _ in range(9):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_key)  # Simplified key schedule
    
    # Final round
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_key)
    
    return matrix_to_bytes(state)

def inverse_sub_bytes(state):
    """Inverse SubBytes transformation."""
    for i in range(4):
        for j in range(4):
            state[i][j] = INVERSE_S_BOX[state[i][j]]
    return state

def inverse_shift_rows(state):
    """Inverse ShiftRows transformation."""
    state[1] = np.roll(state[1], 1)
    state[2] = np.roll(state[2], 2)
    state[3] = np.roll(state[3], 3)
    return state

def inverse_mix_columns(state):
    """Inverse MixColumns transformation."""
    for i in range(4):
        col = state[:, i]
        state[:, i] = [
            galois_multiply(0x0E, col[0]) ^ galois_multiply(0x0B, col[1]) ^ galois_multiply(0x0D, col[2]) ^ galois_multiply(0x09, col[3]),
            galois_multiply(0x09, col[0]) ^ galois_multiply(0x0E, col[1]) ^ galois_multiply(0x0B, col[2]) ^ galois_multiply(0x0D, col[3]),
            galois_multiply(0x0D, col[0]) ^ galois_multiply(0x09, col[1]) ^ galois_multiply(0x0E, col[2]) ^ galois_multiply(0x0B, col[3]),
            galois_multiply(0x0B, col[0]) ^ galois_multiply(0x0D, col[1]) ^ galois_multiply(0x09, col[2]) ^ galois_multiply(0x0E, col[3])
        ]
    return state

def reverse_aes_without_key(ciphertext):
    """Reverse AES encryption without the key."""
    state = convert_to_matrix(ciphertext)
    
    # Reverse final round
    state = inverse_shift_rows(state)
    state = inverse_sub_bytes(state)
    
    # Reverse main rounds
    for _ in range(9):
        state = inverse_mix_columns(state)
        state = inverse_shift_rows(state)
        state = inverse_sub_bytes(state)
    
    return matrix_to_bytes(state)

def recover_key(ciphertext, known_plaintext):
    """Recover the AES key using ciphertext and known plaintext."""
    # Reverse the ciphertext through AES transformations
    reversed_state = reverse_aes_without_key(ciphertext)
    
    # Pad the known plaintext
    padded_plaintext = pad_data(known_plaintext.encode())
    
    # XOR the reversed state with the plaintext to recover the key
    key = bytes([reversed_state[i] ^ padded_plaintext[i] for i in range(16)])
    
    return key

def display_flashing_key_attempt(candidate_key):
    """Display a flashing key attempt on the same line."""
    print(colored(f"\r[+] Trying key: {candidate_key.hex()} ", "yellow"), end="")
    sys.stdout.flush()

def try_ciphertext_combinations(ciphertext, known_plaintext, max_attempts=100000000000000000000000000000000000000000000000000000000000000000000):
    """Try combinations of ciphertext to recover the key."""
    padded_plaintext = pad_data(known_plaintext.encode())
    start_time = time.time()
    keys_tried = 0

    for attempt in range(max_attempts):
        # Generate a modified ciphertext (for demonstration, we use a simple counter)
        modified_ciphertext = bytes([(ciphertext[i] + attempt) % 256 for i in range(16)])
        
        # Reverse the modified ciphertext to get the candidate key
        reversed_state = reverse_aes_without_key(modified_ciphertext)
        candidate_key = bytes([reversed_state[i] ^ padded_plaintext[i] for i in range(16)])
        
        # Display the current attempt
        print(colored(f"\r[+] Trying ciphertext: {modified_ciphertext.hex()} | Key: {candidate_key.hex()} | Attempts: {keys_tried}", "yellow"), end="")
        sys.stdout.flush()
        
        # Verify the candidate key
        test_cipher = encrypt_aes(padded_plaintext, candidate_key)
        if test_cipher == ciphertext:
            print(colored("\n\n[+] Key Recovery Successful!", "green"))
            return candidate_key
        
        keys_tried += 1
        time.sleep(0.01)  # Add slight delay for display
    
    raise KeyRecoveryError(f"\n\n[!] Key recovery failed after {max_attempts} attempts")


def main():
    parser = argparse.ArgumentParser(description="AES Encryption/Decryption Tool")
    parser.add_argument("-e", "--encrypt", action="store_true", help="Enable encryption mode")
    parser.add_argument("-c", "--ciphertext", help="Ciphertext in hex format (for decryption)")
    parser.add_argument("-p", "--plaintext", help="Plaintext string (for encryption/decryption)")
    parser.add_argument("-k", "--key", help="AES key in hex format (32 hex chars)")
    args = parser.parse_args()

    if args.encrypt:
        # Encryption mode
        if not args.key or len(args.key) != 32:
            print(colored("[!] Valid 128-bit key required (32 hex characters)", "red"))
            sys.exit(1)
        
        if not args.plaintext:
            print(colored("[!] Plaintext is required for encryption", "red"))
            sys.exit(1)
        
        key = bytes.fromhex(args.key)
        plaintext = args.plaintext.encode()
        
        # Encrypt the plaintext
        ciphertext = encrypt_aes(plaintext, key)
        
        print(colored("\n[+] Encryption Results:", "green"))
        print(f"Plaintext (hex): {plaintext.hex()}")
        print(f"Key (hex): {key.hex()}")
        print(f"Ciphertext (hex): {ciphertext.hex()}")
    
    else:
        # Decryption mode
        if not args.ciphertext:
            print(colored("[!] Ciphertext is required for decryption", "red"))
            sys.exit(1)
        
        if not args.plaintext:
            print(colored("[!] Known plaintext is required for key recovery", "red"))
            sys.exit(1)
        
        try:
            ciphertext = bytes.fromhex(args.ciphertext)
        except ValueError:
            print(colored("[!] Invalid ciphertext format", "red"))
            sys.exit(1)
        
        if len(ciphertext) != 16:
            print(colored("[!] Ciphertext must be 16 bytes", "red"))
            sys.exit(1)
        
        print(colored("[+] Starting key recovery via ciphertext combinations...", "cyan"))
        
        try:
            # Try combinations of the ciphertext to recover the key
            recovered_key = try_ciphertext_combinations(ciphertext, args.plaintext)
            
            print(colored("\n\n[+] Key Recovery Successful!", "green"))
            print(colored(f"Recovered Key (hex): {recovered_key.hex()}", "cyan"))
            
            # Verify the key
            test_cipher = encrypt_aes(pad_data(args.plaintext.encode()), recovered_key)
            if test_cipher == ciphertext:
                print(colored("[+] Key verification passed!", "green"))
            else:
                print(colored("[!] Key verification failed", "red"))
        
        except KeyRecoveryError as e:
            print(colored(str(e), "red"))

if __name__ == "__main__":
    main()
