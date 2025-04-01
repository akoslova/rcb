# implement the electronic codebook mode that encrypts and decrypts an image
# using AES-128

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from PIL import Image
import numpy as np
import sys
import hashlib

# global variables
S = dict()
T = dict()

def sha256_custom(data: str, tao: int) -> str:
    """Computes a SHA-256 hash and truncates it to tao bits."""
    if tao > 256 or tao <= 0:
        raise ValueError("tao must be between 1 and 256 bits")
    
    full_hash = hashlib.sha256(data).hexdigest()  # Full 256-bit hash (hex)
    truncated_hash = full_hash[:tao // 4]  # Each hex digit = 4 bits
    
    return truncated_hash

def scb_encrypt(cipher, data, tao, sigma, key):
    C = ''
    # loop over every 16 bits of the data
    for i in range(0, len(data), 16):
        M_i = data[i:i+16]
        print(M_i)
        h = sha256_custom(M_i, tao)
        print(h)
        if S[h] == None:
            C_i = cipher.encrypt(M_i)
            S[h] = '0' * sigma
        else:
            R = '0' * (16 - sigma - tao) + S[h] + h
            C_i = cipher.encrypt(R ^ K)
            counter = int(S[h]) + 1
            S[h] = '0' * (16-len(str(counter))) + str(counter)
        C += C_i
    return C

    encrypted_data = cipher.encrypt(data)
    return encrypted_data

def encrypt_image(image_path, tao, sigma, key):
    # open the image
    img = Image.open(image_path)
    img = img.convert('RGB')
    img_data = np.array(img)

    # create the AES cipher
    cipher = AES.new(key, AES.MODE_ECB)

    # Flatten the image data and pad it to a multiple of 16 bytes
    flat_data = img_data.flatten()
    padded_data = pad(flat_data.tobytes(), AES.block_size)

    # Encrypt the padded data
    # encrypted_data = cipher.encrypt(padded_data)
    encrypted_data = scb_encrypt(cipher, padded_data, tao, sigma, key)

    # Convert encrypted data back to an array and reshape it
    encrypted_array = np.frombuffer(encrypted_data, dtype=np.uint8)
    encrypted_image = encrypted_array[:flat_data.size].reshape(img_data.shape)

    # Save the encrypted image
    img_enc = Image.fromarray(encrypted_image)
    img_name = image_path.split('.')[0] + '_SCB_encrypted.png'
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
  
    img_name = image_path.split('.')[0] + '_SCB_encdec.png'
    img_dec.save(img_name)


def main():
    # check for the correct number of arguments
    if len(sys.argv) > 4 or len(sys.argv) < 3:
        print('Usage: python ecb.py <image_path> <key> <mode> or python ecb.py <image_path> <mode>')
        sys.exit(1)

    # get the image path
    image_path = sys.argv[1]

    tao = 32
    sigma = 8

    if len(sys.argv) == 4:
        # get the key and mode
        key = sys.argv[2].encode()
        mode = sys.argv[3]
    else:
        key = '0123456789abcdef0123456789abcdef'.encode()
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

# Usage: python ecb.py <image_path> <key> <mode> or python ecb.py <image_path> <mode>
# Example: python ecb.py image.png key enc or python ecb.py image.png enc
# Example: python ecb.py encrypted_image.png key encdec or python ecb.py encrypted_image.png encdec
