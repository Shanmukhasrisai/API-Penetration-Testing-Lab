"""Basic tests for the API Penetration Testing Lab"""
import pytest
import sys
from pathlib import Path


def test_import_api():
    """Test that api.py can be imported successfully"""
    try:
        import api
        assert api is not None
    except ImportError as e:
        pytest.fail(f"Failed to import api module: {e}")


def test_basic_pass():
    """A basic test that always passes to ensure pytest runs successfully"""
    assert True


def test_labs_directory_exists():
    """Test that the labs directory exists"""
    labs_dir = Path("labs")
    assert labs_dir.exists(), "labs directory should exist"
    assert labs_dir.is_dir(), "labs should be a directory"


def test_api_file_exists():
    """Test that api.py file exists"""
    api_file = Path("api.py")
    assert api_file.exists(), "api.py file should exist"
    assert api_file.is_file(), "api.py should be a file"
