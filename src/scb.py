# implement the electronic codebook mode that encrypts and decrypts an image
# using AES-128

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from PIL import Image
import numpy as np
import sys
import hashlib

# global variables
S = {}
T = {}

# should work
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

def scb_encrypt(cipher, data, tao, sigma, key):
    """Encrypts data using the SCB mode of AES encryption.
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
    if tao + sigma > 16:
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
            S[h] = b'0' * sigma

        else:
            R = b'0' * (16 - sigma - tao) + S[h] + h
            # XOR each pair of bytes and build a new bytes object
            # zip(a, b) pairs up each byte from a and b
            C_i = cipher.encrypt(bytes([x ^ y for x, y in zip(R, key)]))
            counter = int.from_bytes(S[h], byteorder='big')
            counter = (counter + 1) % MAX_COUNTER
            S[h] = counter.to_bytes(16, byteorder='big')
        C += C_i

    return C


def encrypt_image(image_path, tao, sigma, key):
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
    encrypted_data = scb_encrypt(cipher, padded_data, tao, sigma, key)

    # Convert encrypted data back to an array and reshape it
    encrypted_array = np.frombuffer(encrypted_data, dtype=np.uint8)
    encrypted_image = encrypted_array[:flat_data.size].reshape(img_data.shape)

    # Save the encrypted image
    img_enc = Image.fromarray(encrypted_image)
    img_name = image_path.split('.')[0] + '_SCB_tao_' + str(tao) + '_sigma_' + str(sigma) + '_enc.png'
    img_enc.save(img_name)

def encrypt_decrypt_image(image_path, key):
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
    encrypted_data = cipher.encrypt(padded_data)

    # Decrypt the data
    decrypted_data = cipher.decrypt(encrypted_data)

    # Unpad the decrypted data
    unpadded_data = unpad(decrypted_data, AES.block_size)

    # Convert decrypted data back to an array and reshape it
    decrypted_array = np.frombuffer(unpadded_data, dtype=np.uint8)
    decrypted_image = decrypted_array.reshape(img_data.shape)

    # Save the decrypted image
    img_dec = Image.fromarray(decrypted_image)
  
    img_name = image_path.split('.')[0] + '_SCB_tao_' + str(tao) + '_sigma_' + str(sigma) + '_encdec.png'
    img_dec.save(img_name)


def main():
    # check for the correct number of arguments
    if len(sys.argv) > 4 or len(sys.argv) < 3:
        print('Usage: python ecb.py <image_path> <key> <mode> or python ecb.py <image_path> <mode>')
        sys.exit(1)

    # get the image path
    image_path = sys.argv[1]

    tao = 14
    sigma = 2

    if len(sys.argv) == 4:
        # get the key and mode
        key = sys.argv[2].encode()
        mode = sys.argv[3]
    else:
        key_str = "MySecretKey12345"  # 16 characters
        key = key_str.encode('utf-8')  # Now it's a 16-byte key
        mode = sys.argv[2]

    # encrypt or decrypt the image
        if mode == 'enc':
            encrypt_image(image_path, tao, sigma, key)
        elif mode == 'encdec':
            encrypt_decrypt_image(image_path, key)
        else:
            print('Invalid mode')
            sys.exit(1)

if __name__ == '__main__':
    main()

# Usage: python scb.py <image_path> <key> <mode> or python scb.py <image_path> <mode>
# Example: python scb.py image.png key enc or python scb.py image.png enc
# Example: python scb.py encrypted_image.png key encdec or python scb.py encrypted_image.png encdec
