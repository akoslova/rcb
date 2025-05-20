# implement the electronic codebook mode that encrypts and decrypts an image
# using AES-128

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from PIL import Image
import numpy as np
import sys
import os

def encrypt_image(image_path, key):
    """
    Encrypts an image using AES-128 in ECB mode 
    and saves the image in /img/sec/ECB.
    Args:
        image_path (str): The path to the image.
        key (bytes): The encryption key (must be 16 bytes).
    """
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
    encrypted_data = cipher.encrypt(padded_data)

    # Convert encrypted data back to an array and reshape it
    encrypted_array = np.frombuffer(encrypted_data, dtype=np.uint8)
    encrypted_image = encrypted_array[:flat_data.size].reshape(img_data.shape)

    # Save the encrypted image
    img_enc = Image.fromarray(encrypted_image)

    img_name = image_path.split('/')[-1].split('.')[0] + '_ECB_enc.png'

    current_dir = os.path.dirname(__file__)
    parent_dir = os.path.abspath(os.path.join(current_dir, ".."))
    enc_img_path = os.path.join(parent_dir, "img", "sec", "ECB", img_name)
    img_enc.save(enc_img_path)

def encrypt_decrypt_image(image_path, key):
    """
    Encrypts and then decrypts an image using AES-128 in ECB mode
    and saves the image in /img/cor/ECB.
    Args:
        image_path (str): The path to the image.
        key (bytes): The encryption key (must be 16 bytes).
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
    encrypted_data = cipher.encrypt(padded_data)

    # Decrypt the data
    decrypted_data = cipher.decrypt(encrypted_data)

    # Convert decrypted data back to an array and reshape it
    decrypted_array = np.frombuffer(decrypted_data, dtype=np.uint8)
    decrypted_image = decrypted_array[:flat_data.size].reshape(img_data.shape)

    # Save the decrypted image
    img_dec = Image.fromarray(decrypted_image)

    img_name = image_path.split('/')[-1].split('.')[0] + '_ECB_encdec.png'

    current_dir = os.path.dirname(__file__)
    parent_dir = os.path.abspath(os.path.join(current_dir, ".."))
    dec_img_path = os.path.join(parent_dir, "img", "cor", "ECB", img_name)
    img_dec.save(dec_img_path)


def main():
    # check for the correct number of arguments
    if len(sys.argv) > 4 or len(sys.argv) < 3:
        print('Usage: python ecb.py <image_path> <key> <mode> or python ecb.py <image_path> <mode>')
        sys.exit(1)

    # get the image path
    current_dir = os.path.dirname(__file__)
    parent_dir = os.path.abspath(os.path.join(current_dir, ".."))
    image_path = os.path.join(parent_dir, "img", "original", sys.argv[1])
    #image_path = sys.argv[1]

    if len(sys.argv) == 4:
        # get the key and mode
        key = sys.argv[2].encode()
        mode = sys.argv[3]
    else:
        key = '0123456789abcdef0123456789abcdef'.encode()
        mode = sys.argv[2]

    # encrypt or decrypt the image
        if mode == 'enc':
            encrypt_image(image_path, key)
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
