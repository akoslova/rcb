# implement the electronic codebook mode that encrypts and decrypts an image
# using AES-128

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from PIL import Image
import numpy as np
import sys
import os

def compare(image_path_1, image_path_2):
    # open the image 1
    img_1 = Image.open(image_path_1)
    img_1 = img_1.convert('RGB')
    img_data_1 = np.array(img_1)

    # open the image 1
    img_2 = Image.open(image_path_2)
    img_2 = img_2.convert('RGB')
    img_data_2 = np.array(img_2)
    
    # Flatten the image data and pad it to a multiple of 16 bytes
    flat_data_1 = img_data_1.flatten()
    flat_data_2 = img_data_2.flatten()

    # store result flat data
    flat_data_res = np.zeros(flat_data_1.shape, dtype=np.uint8)

    # compare flat data 1 and 2 and if there is a difference, put a 1 in the result flat data
    for i in range(flat_data_1.size):
        if flat_data_1[i] != flat_data_2[i]:
            flat_data_res[i] = 255

    # Convert decrypted data back to an array and reshape it
    compared_image = flat_data_res.reshape(img_data_1.shape)

    # Save the decrypted image
    img_compare = Image.fromarray(compared_image)

    img_name = 'compare_'  + image_path_1.split('/')[-1].split('.')[0] + '_' + image_path_2.split('/')[-1].split('.')[0] + '.png'

    current_dir = os.path.dirname(__file__)
    parent_dir = os.path.abspath(os.path.join(current_dir, ".."))
    img_path_compare = os.path.join(parent_dir, "test", "compare", img_name)
    img_compare.save(img_path_compare)


def main():
    # check for the correct number of arguments
    if len(sys.argv) != 3:
        print('Usage: python compare.py <image_path_1> <image_path_2> ')
        sys.exit(1)

    # get the image path
    current_dir = os.path.dirname(__file__)
    parent_dir = os.path.abspath(os.path.join(current_dir, ".."))
    image_path_1 = os.path.join(parent_dir, "test", "cor", sys.argv[1])
    image_path_2 = os.path.join(parent_dir, "test", "cor", sys.argv[2])

    compare(image_path_1, image_path_2)

if __name__ == '__main__':
    main()

# Usage: python compare.py <image_path_1> <image_path_2> 
# Example: python compare.py image1.png image2.png
