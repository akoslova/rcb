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
    
    # sha256: input any size, output 256 bits
    # .digest provides raw bytes
    full_hash = hashlib.sha256(data).digest()  

    truncated_hash = full_hash[:tao]  # truncate to tao bits
    
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
    # check if sigma is between 1 and 16
    if sigma > 16 or sigma <= 0:
        raise ValueError("sigma must be between 1 and 16")
    
    # allow only tao between 1 and 16
    if tao > 16 or tao <= 0:
        raise ValueError("tao must be between 1 and 16")

    # check that the sum of tao and sigma is less than 16
    if (tao + sigma) > 16:
        raise ValueError("tao + sigma must be less than 16")

    # check if the key is 16 bytes
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes (128 bits)")
    
    # cipher bytes
    C = b''

    # maximum counter value
    MAX_COUNTER = 2 ** (8 * sigma)

    # loop over every 16 bits of the data
    for i in range(0, len(data), 16):

        M_i = data[i:i+16]
        h = sha256_custom(M_i, tao)

        if h not in S:
            C_i = cipher.encrypt(M_i)
            S[h] = 0

        elif (S[h] < MAX_COUNTER):
            R = b'\x00' * (16 - sigma - tao) + S[h].to_bytes(sigma, 'big') + h
            # XOR each pair of bytes and build a new bytes object
            # zip(a, b) pairs up each byte from a and b
            C_i = cipher.encrypt(bytes([x ^ y for x, y in zip(R, key)]))
            S[h] = S[h] + 1
        
        else:
            C_i = os.urandom(16)
            
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
    if sigma > 16 or sigma <= 0:
        raise ValueError("sigma must be between 1 and 16")
    
    # allow only tao between 1 and 16
    if tao > 16 or tao <= 0:
        raise ValueError("tao must be between 1 and 16")

    # check that the sum of tao and sigma is less than 16
    if (tao + sigma) > 16:
        raise ValueError("tao + sigma must be less than 16")

    # check if the key is 16 bytes
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes (128 bits)")
    
    # cipher bytes
    M = b''

    # max hash
    MAX_HASH = 2 ** (8 * tao)

    # max counter
    MAX_COUNTER = 2 ** (8 * sigma)

    # threshold for R
    threshold = 2**(tao*8 + sigma*8)

    # loop over every 16 bits of the data
    for i in range(0, len(data), 16):

        # C_i 16 bytes
        C_i = data[i:i+16]
        # M_i 16 bytes
        M_i = cipher.decrypt(C_i)
        # XOR key with M_i and convert to an int
        R = int.from_bytes(bytes(a ^ b for a, b in zip(key, M_i)), byteorder='big')
        h_int = R % MAX_HASH
        h = h_int.to_bytes(tao, byteorder='big')

        if R < threshold and h in T:
            M_i = T[h]

        else:
            h = sha256_custom(M_i, tao)
            T[h] = M_i
        M += M_i

    # check if the length of M is a multiple of 16
    return M


def encrypt_image(image_path, sigma, tao, key):
    """
    Encrypts an image using the RCB mode and saves it in /img/sec/RCB.
    Args:
        image_path (str): The path to the image.
        sigma (int): The number of bits to use for the counter.
        tao (int): The number of bits to truncate the hash to.
        key (bytes): The encryption key.
    """
    # open the image
    img = Image.open(image_path)
    img = img.convert('RGB')
    # create an array with rgb values (integers between 0 and 255): one pixel is [R,G,B]
    img_data = np.array(img)

    # create the AES cipher
    cipher = AES.new(key, AES.MODE_ECB)

    # converts the many [R,G,B] arrays from img_data into one 1D arry [R,G,B,R,G,B,...]
    flat_data = img_data.flatten()
    # the 1D array is converted to bytes and ensures that the length is a multiple of 16 bytes 
    # for it to be AES compatible
    padded_data = pad(flat_data.tobytes(), AES.block_size)

    # Encrypt the padded data
    encrypted_data = rcb_encrypt(cipher, padded_data, sigma, tao, key)

    # Convert encrypted data back to an array and reshape it
    encrypted_array = np.frombuffer(encrypted_data, dtype=np.uint8)
    encrypted_image = encrypted_array[:flat_data.size].reshape(img_data.shape)

    # Save the encrypted image
    img_enc = Image.fromarray(encrypted_image)

    img_name = image_path.split('/')[-1].split('.')[0] + '_RCB_sigma_' + str(sigma) + '_tao_' + str(tao) + '_enc.png'

    current_dir = os.path.dirname(__file__)
    parent_dir = os.path.abspath(os.path.join(current_dir, ".."))
    enc_img_path = os.path.join(parent_dir, "img", "sec", "RCB", img_name)
    img_enc.save(enc_img_path)

def encrypt_decrypt_image(image_path, sigma, tao, key):
    """
    Encrypts and then decrypts an image using the RCB mode
    and saves the image in /img/cor/RCB.
    Args:
        image_path (str): The path to the image.
        sigma (int): The number of bits to use for the counter.
        tao (int): The number of bits to truncate the hash to.
        key (bytes): The encryption key.
    """
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

    img_name = image_path.split('/')[-1].split('.')[0] + '_RCB_sigma_' + str(sigma) + '_tao_' + str(tao) + '_encdec.png'

    current_dir = os.path.dirname(__file__)
    parent_dir = os.path.abspath(os.path.join(current_dir, ".."))
    dec_img_path = os.path.join(parent_dir, "img", "cor", "RCB", img_name)
    img_dec.save(dec_img_path)

def main():
    # check for the correct number of arguments
    if len(sys.argv) > 6 or len(sys.argv) < 5:
        print('Usage: python rcb.py <image_path> <key> <sigma> <tao> <mode> or python rcb.py <image_path> <sigma> <tao> <mode>')
        sys.exit(1)

    # get the image path
    current_dir = os.path.dirname(__file__)
    parent_dir = os.path.abspath(os.path.join(current_dir, ".."))
    image_path = os.path.join(parent_dir, "img", "original", sys.argv[1])

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

    # encrypt or decrypt the image
        if mode == 'enc':
            encrypt_image(image_path, sigma, tao, key)
        elif mode == 'encdec':
            encrypt_decrypt_image(image_path, sigma, tao, key)
        else:
            print('Invalid mode')
            sys.exit(1)

if __name__ == '__main__':
    main()

# Usage: python rcb.py <image_path> <key> <sigma> <tao> <mode> or python rcb.py <image_path> <sigma> <tao> <mode>
# Example: python rcb.py image.png key 2 2 enc or python rcb.py image.png 2 2 enc
# Example: python rcb.py encrypted_image.png key 2 2 encdec or python rcb.py encrypted_image.png 2 2 encdec
