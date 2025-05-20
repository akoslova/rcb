import pytest
import sys
import os
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad

# Add the src folder to the path so we can import from src.rcb
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from rcb import sha256_custom, rcb_encrypt, rcb_decrypt, S, T

@pytest.fixture(autouse=True)
def clear_rcb_state():
    """Clear global state before each test."""
    S.clear()
    T.clear()


def test_sha256_truncation():
    data = b"1234567890abcdef"
    tao = 8  # 8 bytes
    truncated = sha256_custom(data, tao)
    assert isinstance(truncated, bytes)
    assert len(truncated) == tao


def test_encrypt_decrypt_round_trip():
    key = b"MySecretKey12345"  # 16 bytes
    cipher = AES.new(key, AES.MODE_ECB)

    sigma = 2
    tao = 2

    original_data = os.urandom(64)
    padded_data = pad(original_data, AES.block_size)

    encrypted = rcb_encrypt(cipher, padded_data, sigma, tao, key)
    decrypted = rcb_decrypt(cipher, encrypted, sigma, tao, key)

    # Truncate to the original padded length
    assert decrypted[:len(padded_data)] == padded_data


def test_invalid_key_length():
    short_key = b"short_key"
    cipher = AES.new(b"MySecretKey12345", AES.MODE_ECB)
    data = pad(os.urandom(32), AES.block_size)

    with pytest.raises(ValueError):
        rcb_encrypt(cipher, data, sigma=2, tao=2, key=short_key)


@pytest.mark.parametrize("sigma,tao", [
    (0, 2),  # Invalid sigma
    (2, 0),  # Invalid tao
    (9, 8),  # tao + sigma = 17 > 16
    (17, 1), # sigma too large
])
def test_invalid_sigma_tao(sigma, tao):
    key = b"MySecretKey12345"
    cipher = AES.new(key, AES.MODE_ECB)
    data = pad(os.urandom(32), AES.block_size)

    with pytest.raises(ValueError):
        rcb_encrypt(cipher, data, sigma=sigma, tao=tao, key=key)