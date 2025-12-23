# k1.py
from v1helper import *
import itertools

K1 = """PFFWWBMDNSXCVIZPBQJYTQQFXBTTSCICQHUOIMGRFJNSJEDWNOGRVHWEMVMU""" # part of K1 for testing

KLEN = 7
KEY_LEN = 10
TOP_N = 5
MAX_KEYS = 5000 # 5000 for test, suggest 15000 for observations

FROZEN_POS = {}  # positions you want to lock

def get_top_letters_per_position(ciphertext, key_len, top_n=TOP_N):
    columns = []
    for i in range(key_len):
        col_text = ciphertext[i::key_len]
        ranked = sorted([(chi_squared_score(caesar_decrypt(col_text, s)), I2A[s]) for s in range(len(ALPHABET))], key=lambda x: x[0])
        columns.append([letter for _, letter in ranked[:top_n]])
    return columns

def break_vigenere(ciphertext, key_len=KEY_LEN, top_n=TOP_N):
    results = []
    ciphertext = clean(ciphertext)
    top_letters_per_position = get_top_letters_per_position(ciphertext, key_len, top_n)
    if len(FROZEN_POS) > 0:
        print(f"Applying freezes at positions: {FROZEN_POS}\n")
    else: 
        print("No freezes applied. Check top positions and adjust for freezing.\n")
    for combination in itertools.product(*top_letters_per_position):
        key = list(combination)
        for pos, letter in FROZEN_POS.items():
            key[pos] = letter
        key = ''.join(key)
        plaintext = vigenere_decrypt(ciphertext, key)
        score = english_score(plaintext) + phrase_boost(plaintext)
        results.append((score, key, plaintext))
    return sorted(results, key=lambda x: x[0])

def main():
    ciphertext = clean(K1)

    for key_len in range(KLEN, KEY_LEN + 1):
        print(f"\n{'='*20}")
        print(f"Testing key length = {key_len}")
        print(f"{'='*60}\n")

        results = break_vigenere(ciphertext, key_len=key_len, top_n=TOP_N)

        print("Top candidates:\n")
        for score, key, plaintext in results[:20]:
            print(f"{key:10} {score:8.3f} {plaintext[:60]}")

        # pattern analysis only on best result
        best_plaintext = results[0][2]
        patterns = find_patterns(best_plaintext, min_len=5)

        if patterns:
            print("\nRepeated patterns (length >=5):")
            for p, positions in patterns.items():
                print(f"{p} at {positions}")
        else:
            print("\nNo strong repeated patterns found.")


if __name__ == "__main__":
    main()
