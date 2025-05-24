import os
import tempfile
import shutil
import numpy as np
from PIL import Image
from Cryptodome.Random import get_random_bytes

import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from ecb import encrypt_image, encrypt_decrypt_image

def create_test_image(path, size=(64, 64), color=(255, 0, 0)):
    img = Image.new('RGB', size, color)
    img.save(path)

def images_equal(img1_path, img2_path):
    img1 = np.array(Image.open(img1_path))
    img2 = np.array(Image.open(img2_path))
    return np.array_equal(img1, img2)

def test_ecb_encrypt_and_decrypt():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Setup directory structure
        img_original_dir = os.path.join(tmpdir, 'img', 'original')
        img_sec_dir = os.path.join(tmpdir, 'img', 'sec', 'ECB')
        img_cor_dir = os.path.join(tmpdir, 'img', 'cor', 'ECB')
        os.makedirs(img_original_dir)
        os.makedirs(img_sec_dir)
        os.makedirs(img_cor_dir)

        # Patch __file__ reference inside ecb module
        ecb_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../src', 'ecb.py'))
        with open(ecb_path, 'r') as f:
            script = f.read()

        script = script.replace(
            "current_dir = os.path.dirname(__file__)",
            f"current_dir = '{tmpdir}'"
        )
        exec_globals = {}
        exec(script, exec_globals)

        # Create test image
        img_name = 'test_img.png'
        img_path = os.path.join(img_original_dir, img_name)
        create_test_image(img_path)

        key = b'0123456789abcdef'

        # Encrypt and check if output exists
        encrypt_image(img_path, key)
        enc_path = os.path.join(img_sec_dir, 'test_img_ECB_enc.png')

        # Encrypt and decrypt
        encrypt_decrypt_image(img_path, key)
        dec_path = os.path.join(img_cor_dir, 'test_img_ECB_encdec.png')

