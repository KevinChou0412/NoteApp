#!/usr/bin/env python3
import argparse
import math
import string


ENGLISH = (
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,
    0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,
    0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,
    0.00978, 0.02360, 0.00150, 0.01974, 0.00074,
)


def decrypt(text, shift):
    output = []
    for char in text:
        alphabet = string.ascii_uppercase if char.isupper() else string.ascii_lowercase
        if char in alphabet:
            output.append(alphabet[(alphabet.index(char) - shift) % 26])
        else:
            output.append(char)
    return "".join(output)


def chi_squared(text):
    letters = [char.lower() for char in text if char.lower() in string.ascii_lowercase]
    if not letters:
        return math.inf
    counts = [letters.count(letter) for letter in string.ascii_lowercase]
    total = len(letters)
    return sum((observed - total * expected) ** 2 / (total * expected)
               for observed, expected in zip(counts, ENGLISH))


def rank_shifts(ciphertext):
    return sorted(((chi_squared(decrypt(ciphertext, shift)), shift,
                    decrypt(ciphertext, shift)) for shift in range(26)))


def main():
    parser = argparse.ArgumentParser(description="Rank Caesar shifts using English letter frequencies.")
    parser.add_argument(
        "text",
        nargs="?",
        default="Wklv lv d whdfklqj whaw. Wkh txlfn eurzq ira mxpsv ryhu wkh odcb grj.",
    )
    args = parser.parse_args()
    print("Frequency analysis is a guess, especially for short or non-English text.")
    for score, shift, candidate in rank_shifts(args.text)[:5]:
        print(f"shift={shift:2d} chi_squared={score:8.2f} {candidate}")


if __name__ == "__main__":
    main()
