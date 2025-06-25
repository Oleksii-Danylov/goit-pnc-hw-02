from collections import defaultdict, Counter
from math import gcd
from functools import reduce

def find_repeats(text, length=3):
    text = ''.join(filter(str.isalpha, text.upper()))
    repeats = defaultdict(list)
    for i in range(len(text) - length + 1):
        seq = text[i:i+length]
        repeats[seq].append(i)
    return {seq: pos for seq, pos in repeats.items() if len(pos) > 1}

def get_distances(positions):
    distances = []
    for pos_list in positions.values():
        for i in range(len(pos_list) - 1):
            distances.append(pos_list[i+1] - pos_list[i])
    return distances

def kasiski_examination(ciphertext, seq_length=3):
    repeats = find_repeats(ciphertext, seq_length)
    distances = get_distances(repeats)
    if not distances:
        return None
    estimated_key_length = reduce(gcd, distances)
    if estimated_key_length == 1:
        return None
    return estimated_key_length

def kasiski_try_all(ciphertext):
    for seq_len in range(3, 6):
        estimated_key_length = kasiski_examination(ciphertext, seq_len)
        if estimated_key_length is not None:
            print(f"Довжина ключа з послідовністю символів {seq_len}: {estimated_key_length}")
            return estimated_key_length
    print("Не знайдено необхідну довжину ключа")
    return None

def split_text(text, key_length):
    text = ''.join(filter(str.isalpha, text.upper()))
    return [text[i::key_length] for i in range(key_length)]


def frequency_analysis(text):
    frequencies = Counter(text)
    total = len(text)
    freq_percent = {char: count/total for char, count in frequencies.items()}
    return freq_percent


def caesar_shift_decrypt(char, shift):
    return chr((ord(char) - ord('A') - shift) % 26 + ord('A'))


def find_caesar_key(column):
    english_freq = {
        'E': 0.127, 'T': 0.091, 'A': 0.082, 'O': 0.075, 'I': 0.07,
        'N': 0.067, 'S': 0.063, 'H': 0.061, 'R': 0.06, 'D': 0.043,
        'L': 0.04, 'C': 0.028, 'U': 0.028, 'M': 0.024, 'W': 0.024,
        'F': 0.022, 'G': 0.02, 'Y': 0.02, 'P': 0.019, 'B': 0.015,
        'V': 0.01, 'K': 0.008, 'J': 0.002, 'X': 0.0015, 'Q': 0.001, 'Z': 0.0005
    }
    min_chi_sq = None
    best_shift = 0
    for shift in range(26):
        decrypted = [caesar_shift_decrypt(c, shift) for c in column]
        freq = frequency_analysis(decrypted)
        chi_sq = 0
        for letter in english_freq:
            observed = freq.get(letter, 0)
            expected = english_freq[letter]
            chi_sq += ((observed - expected) ** 2) / expected
        if min_chi_sq is None or chi_sq < min_chi_sq:
            min_chi_sq = chi_sq
            best_shift = shift
    return best_shift


def vigenere_decrypt_with_key(ciphertext, key):
    ciphertext = ''.join(filter(str.isalpha, ciphertext.upper()))
    key = key.upper()
    plaintext = []
    for i, char in enumerate(ciphertext):
        k = ord(key[i % len(key)]) - ord('A')
        p = (ord(char) - ord('A') - k) % 26
        plaintext.append(chr(p + ord('A')))
    return ''.join(plaintext)

def vigenere_encrypt(plaintext, key):
    plaintext = ''.join(filter(str.isalpha, plaintext.upper()))
    key = key.upper()
    ciphertext = []
    for i, char in enumerate(plaintext):
        k = ord(key[i % len(key)]) - ord('A')
        c = (ord(char) - ord('A') + k) % 26
        ciphertext.append(chr(c + ord('A')))
    return ''.join(ciphertext)


if __name__ == "__main__":
    plaintext = """
    The artist is the creator of beautiful things. To reveal art and conceal the artist is art's aim. 
    The critic is he who can translate into another manner or a new material his impression of beautiful things. 
    The highest, as the lowest, form of criticism is a mode of autobiography. Those who find ugly meanings in beautiful things are corrupt without being charming. 
    This is a fault. Those who find beautiful meanings in beautiful things are the cultivated. For these there is hope. 
    They are the elect to whom beautiful things mean only Beauty. There is no such thing as a moral or an immoral book. 
    Books are well written, or badly written. That is all. The nineteenth-century dislike of realism is the rage of Caliban seeing his own face in a glass. 
    The nineteenth-century dislike of Romanticism is the rage of Caliban not seeing his own face in a glass. The moral life of man forms part of the subject matter of the artist, 
    but the morality of art consists in the perfect use of an imperfect medium. No artist desires to prove anything. 
    Even things that are true can be proved. No artist has ethical sympathies. An ethical sympathy in an artist is an unpardonable mannerism of style. 
    No artist is ever morbid. The artist can express everything. Thought and language are to the artist instruments of an art. 
    Vice and virtue are to the artist materials for an art. From the point of view of form, the type of all the arts is the art of the musician. 
    From the point of view of feeling, the actor's craft is the type. All art is at once surface and symbol. Those who go beneath the surface do so at their peril. 
    Those who read the symbol do so at their peril. It is the spectator, and not life, that art really mirrors. Diversity of opinion about a work of art shows that the work is new, complex, vital. 
    When critics disagree the artist is in accord with himself. We can forgive a man for making a useful thing as long as he does not admire it. 
    The only excuse for making a useless thing is that one admires it intensely. All art is quite useless.
    """

    key = "CRYPTOGRAPHY"


    ciphertext = vigenere_encrypt(plaintext, key)
    print(f"Зашифрований текст:\n{ciphertext}\n")

    estimated_key_length = kasiski_try_all(ciphertext)

    if estimated_key_length is not None:
        columns = split_text(ciphertext, estimated_key_length)
        key_shifts = [find_caesar_key(col) for col in columns]
        found_key = ''.join(chr(shift + ord('A')) for shift in key_shifts)
        print(f"\nЗнайдений ключ частотний аналіз : {found_key}")

        decrypted_text = vigenere_decrypt_with_key(ciphertext, found_key)
        print(decrypted_text)
    else:
        print("Не вдалося знайти ключ для дешифрування.")

