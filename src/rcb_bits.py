# implement the randomised codebook mode that encrypts and decrypts an image
# using AES-128

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from PIL import Image
import numpy as np
import sys
import hashlib
import os

# global variables - RCB look-up tables
S = {}
T = {}

def sha256_custom(data, tao):
    """Computes a SHA-256 hash and truncates it to tao bits.
    Args:
        data (str): The input data to hash - 16 bytes.
        tao (int): The number of bits to truncate the hash to - between 1 and 128.
    Returns:
        str: The truncated hash as a hexadecimal string - 16 bytes.
    """
    # convert data from binary string to bytes
    data_bytes = int(data, 2).to_bytes(len(data) // 8, byteorder='big')
    
    # sha256: input any size, output 256 bits
    # .digest provides raw bytes
    full_hash = hashlib.sha256(data_bytes).digest()  

    # converet the full_hash into a binary string
    full_hash_bits = ''.join(format(byte, '08b') for byte in full_hash)

    truncated_hash = full_hash_bits[:tao]  # truncate to tao bits
    
    return truncated_hash

def rcb_encrypt(cipher, data, sigma, tao, key):
    """Encrypts data using the RCB mode.
    Args:
        cipher (AES): The AES cipher object.
        data (bytes): The data to encrypt.
        tao (int): The number of bits to truncate the hash to.
        sigma (int): The number of bits to use for the counter.
        key (bytes): The encryption key.
    Returns:
        C (str): The encrypted data in bytes.
    """
    # check if sigma is between 1 and 128
    if sigma > 128 or sigma <= 0:
        raise ValueError("sigma must be between 1 and 128")
    
    # allow only tao between 1 and 128
    if tao > 128 or tao <= 0:
        raise ValueError("tao must be between 1 and 128")

    # check that the sum of tao and sigma is less than 16
    if (tao + sigma) > 128:
        raise ValueError("tao + sigma must be less than 128")

    # check if the key is 16 bytes
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes (128 bits)")
    
    # convert key to binary string
    key_bits = ''.join(format(byte, '08b') for byte in key)

    # cipher binary string
    C = ''

    # maximum counter value
    MAX_COUNTER = 2 ** sigma

    # convert data from bytes to binary string
    data_bits = ''.join(format(byte, '08b') for byte in data)

    # loop over every 16 bits of the data
    for i in range(0, len(data_bits), 128):

        M_i = data_bits[i:i+128]
        h = sha256_custom(M_i, tao)

        if h not in S:
            # convert M_i to bytes
            M_i_bytes = int(M_i, 2).to_bytes(16, byteorder='big')
            C_i_bytes = cipher.encrypt(M_i_bytes)
            # convert C_i to binary string
            C_i = ''.join(format(byte, '08b') for byte in C_i_bytes)
            S[h] = 0

        elif (S[h] < MAX_COUNTER):
            R = '0' * (128 - sigma - tao) + format(S[h], 'b') + h
            # XOR the bits between R and key
            R_key_XORed = int(R, 2) ^ int(key_bits, 2)
            C_i_bytes = cipher.encrypt(R_key_XORed.to_bytes(16, byteorder='big'))
            # convert C_i to binary string
            C_i = ''.join(format(byte, '08b') for byte in C_i_bytes)
            S[h] = S[h] + 1
        
        else:
            C_i_bytes = os.urandom(16)
            # convert C_i to binary string
            C_i = ''.join(format(byte, '08b') for byte in C_i_bytes)
            
        C += C_i

    return C

def rcb_decrypt(cipher, data, sigma, tao, key):
    """Decrypts data using the RCB mode.
    Args:
        cipher (AES): The AES cipher object.
        data (bytes): The data to decrypt.
        tao (int): The number of bits to truncate the hash to.
        sigma (int): The number of bits to use for the counter.
        key (bytes): The encryption key.
    Returns:
        M (str): The decrypted data in bytes.
    """
    # check if sigma is between 1 and 16
    if sigma > 128 or sigma <= 0:
        raise ValueError("sigma must be between 1 and 128")
    
    # allow only tao between 1 and 16
    if tao > 128 or tao <= 0:
        raise ValueError("tao must be between 1 and 128")

    # check that the sum of tao and sigma is less than 16
    if (tao + sigma) > 128:
        raise ValueError("tao + sigma must be less than 128")

    # check if the key is 16 bytes
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes (128 bits)")
    
    # cipher bytes
    M = ''

    # max hash
    MAX_HASH = 2 ** (tao)

    # max counter
    MAX_COUNTER = 2 ** (sigma)

    # threshold for R
    threshold = 2**(MAX_HASH + MAX_COUNTER)

    # convert key to binary string
    key_bits = ''.join(format(byte, '08b') for byte in key)

    # convert data from bytes to binary string
    # data_bits = ''.join(format(byte, '08b') for byte in data)
    data_bits = data

    # loop over every 16 bits of the data
    for i in range(0, len(data_bits), 128):

        # C_i 128 bits
        C_i = data_bits[i:i+128]
        # M_i 128 bits
        M_i = cipher.decrypt(C_i)
        # XOR key with M_i and convert to an int
        R = key_bits ^ M_i
        h_int = R % MAX_HASH
        h = bin(h_int)

        if R < threshold and h in T:
            M_i = T[h].zfill(128)

        else:
            h = sha256_custom(M_i, tao)
            T[h] = M_i
        M += M_i

    # convert M to bytes
    M = int(M, 2).to_bytes(len(M) // 8, byteorder='big')
    # check if the length of M is a multiple of 16
    return M

def encrypt_decrypt_image(image_path, sigma, tao, key):
    # open the image
    img = Image.open(image_path)
    img = img.convert('RGB')
    img_data = np.array(img)

    # create the AES cipher
    cipher = AES.new(key, AES.MODE_ECB)

    # create the AES cipher
    cipher = AES.new(key, AES.MODE_ECB)
    
    # Flatten the image data and pad it to a multiple of 16 bytes
    flat_data = img_data.flatten()
    padded_data = pad(flat_data.tobytes(), AES.block_size)

    # Encrypt the padded data
    encrypted_data = rcb_encrypt(cipher, padded_data, sigma, tao, key)

    # Decrypt the data
    decrypted_data = rcb_decrypt(cipher, encrypted_data, sigma, tao, key)
    
    # Convert decrypted data back to an array and reshape it
    decrypted_array = np.frombuffer(decrypted_data, dtype=np.uint8)
    decrypted_image = decrypted_array[:flat_data.size].reshape(img_data.shape)

    # Save the decrypted image
    img_dec = Image.fromarray(decrypted_image)

    img_name = image_path.split('/')[-1].split('.')[0] + '_RCB_bits_sigma_' + str(sigma) + '_tao_' + str(tao) + '_encdec.png'

    current_dir = os.path.dirname(__file__)
    parent_dir = os.path.abspath(os.path.join(current_dir, ".."))
    dec_img_path = os.path.join(parent_dir, "test", "bits", img_name)
    img_dec.save(dec_img_path)

def main():
    # check for the correct number of arguments
    if len(sys.argv) > 6 or len(sys.argv) < 5:
        print('Usage: python rcb.py <image_path> <key> <sigma> <tao> <mode> or python rcb.py <image_path> <sigma> <tao> <mode>')
        sys.exit(1)

    # get the image path
    current_dir = os.path.dirname(__file__)
    parent_dir = os.path.abspath(os.path.join(current_dir, ".."))
    image_path = os.path.join(parent_dir, "test", "original", sys.argv[1])

    if len(sys.argv) == 6:
        # get the key and mode
        key = sys.argv[2].encode()
        sigma = int(sys.argv[3])
        tao = int(sys.argv[4])
        mode = sys.argv[5]
    else:
        key_str = "MySecretKey12345"  # 16 characters
        key = key_str.encode('utf-8')  # Now it's a 16-byte key
        sigma = int(sys.argv[2])
        tao = int(sys.argv[3])
        mode = sys.argv[4]

    # encrypt and decrypt the image
        if mode == 'encdec':
            encrypt_decrypt_image(image_path, sigma, tao, key)
        else:
            print('Invalid mode')
            sys.exit(1)

if __name__ == '__main__':
    main()

# Usage: python rcb_bits.py <image_path> <key> <sigma> <tao> <mode> or python rcb_bits.py <image_path> <sigma> <tao> <mode>
# Example: python rcb_bits.py encrypted_image.png key 2 2 encdec or python rcb_bits.py encrypted_image.png 2 2 encdec
