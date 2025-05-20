import pytest
import sys
import os

# Add the src folder to the path so we can import from src.rcb
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from rcb import sha256_custom, rcb_encrypt, rcb_decrypt, S, T

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad
import os

@pytest.fixture(autouse=True)
def clear_rcb_state():
    """Clear global state before each test."""
    S.clear()
    T.clear()