import pytest
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
import os
import numpy as np
import sys

# Add the src folder to the path so we can import from src.scb
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from scb import (
    sha256_custom,
    scb_encrypt,
    scb_decrypt,
    S, T
)

@pytest.fixture(autouse=True)
def clear_rcb_state():
    """Clear global state before each test."""
    S.clear()
    T.clear()

@pytest.fixture
def sample_key():
    return b"MySecretKey12345"  # 16 bytes

@pytest.fixture
def sample_data():
    # 32 bytes (2 AES blocks)
    return pad(b"TestBlock1234567TestBlock7654321", AES.block_size)

# unit test for custom sha256 function
def test_sha256_custom_length():
    data = b"Test input data"
    for tao in range(1, 17):
        h = sha256_custom(data, tao)
        assert isinstance(h, bytes)
        assert len(h) == tao

def test_scb_encrypt_decrypt_roundtrip(sample_key, sample_data):
    cipher = AES.new(sample_key, AES.MODE_ECB)
    S.clear()
    T.clear()

    sigma = 4
    tao = 4
    encrypted = scb_encrypt(cipher, sample_data, sigma, tao, sample_key)
    assert encrypted != sample_data
    assert len(encrypted) == len(sample_data)

    decrypted = scb_decrypt(cipher, encrypted, sigma, tao, sample_key)
    assert decrypted == sample_data

def test_invalid_tao_sigma_key(sample_key, sample_data):
    cipher = AES.new(sample_key, AES.MODE_ECB)

    # invalid sigma value
    with pytest.raises(ValueError):
        scb_encrypt(cipher, sample_data, sigma=-1, tao=4, key=sample_key)

    # invalid tao value
    with pytest.raises(ValueError):
        scb_encrypt(cipher, sample_data, sigma=4, tao=-1, key=sample_key)
    
    # invalid key
    with pytest.raises(ValueError):
        scb_encrypt(cipher, sample_data, sigma=8, tao=9, key=b"short_key")

    # sigma + tao > 16
    with pytest.raises(ValueError):
        scb_encrypt(cipher, sample_data, sigma=10, tao=10, key=sample_key) 

def test_scb_determinism(sample_key):
    cipher = AES.new(sample_key, AES.MODE_ECB)
    S.clear()
    T.clear()
    data = pad(b"ABCD" * 4, AES.block_size)  # 16 bytes

    sigma = 2
    tao = 2
    c1 = scb_encrypt(cipher, data, sigma, tao, sample_key)

    # Reset state
    S.clear()
    T.clear()
    cipher2 = AES.new(sample_key, AES.MODE_ECB)
    c2 = scb_encrypt(cipher2, data, sigma, tao, sample_key)

    assert c1 == c2
