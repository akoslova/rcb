import os
import tempfile
import numpy as np
from PIL import Image
import shutil

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from compare import compare

def create_image(path, color=(255, 0, 0), size=(64, 64)):
    """Creates a solid-color RGB image and saves it to the given path."""
    img = Image.new('RGB', size, color)
    img.save(path)

def test_compare_identical_images(tmp_path, capsys):
    """Test comparing two identical images (expecting 0 differences)."""
    img_dir = tmp_path / "img" / "cor"
    out_dir = tmp_path / "img" / "compare"
    img_dir.mkdir(parents=True)
    out_dir.mkdir(parents=True)

    img_path_1 = img_dir / "image1.png"
    img_path_2 = img_dir / "image2.png"

    create_image(img_path_1)
    create_image(img_path_2)

    # Patch __file__ path resolution in compare.py
    os.environ["FAKE_COMPARE_BASE"] = str(tmp_path)

    # Monkeypatch __file__ handling
    original_file = compare.__globals__.get("__file__")
    compare.__globals__["__file__"] = __file__.replace("test_compare.py", "compare.py")

    try:
        compare(str(img_path_1), str(img_path_2))
    finally:
        # Reset __file__
        if original_file is not None:
            compare.__globals__["__file__"] = original_file

    # Check output from print
    captured = capsys.readouterr()
    assert "Number of differences: 0" in captured.out

def test_compare_different_images(tmp_path, capsys):
    """Test comparing two different images (expecting non-zero differences)."""
    img_dir = tmp_path / "img" / "cor"
    out_dir = tmp_path / "img" / "compare"
    img_dir.mkdir(parents=True)
    out_dir.mkdir(parents=True)

    img_path_1 = img_dir / "image_red.png"
    img_path_2 = img_dir / "image_blue.png"

    create_image(img_path_1, color=(255, 0, 0))
    create_image(img_path_2, color=(0, 0, 255))

    # Patch __file__ path resolution
    original_file = compare.__globals__.get("__file__")
    compare.__globals__["__file__"] = __file__.replace("test_compare.py", "compare.py")

    try:
        compare(str(img_path_1), str(img_path_2))
    finally:
        if original_file is not None:
            compare.__globals__["__file__"] = original_file

    # Check printed output for non-zero differences
    captured = capsys.readouterr()
    assert "Number of differences:" in captured.out
    assert "0" not in captured.out.strip().split()[-1], "Expected some differences"

