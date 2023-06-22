import pytest
from app.monitor import convert_bytes_to_readable

def test_convert_bytes_to_readable():
    """Test convert_bytes_to_readable function."""

    # Test bytes with no units
    assert convert_bytes_to_readable(500) == "500.0"

    # Test kilobytes
    assert convert_bytes_to_readable(1500) == "1.5KB"

    # Test megabytes
    assert convert_bytes_to_readable(1049000) == "1.0MB"

    # Test gigabytes
    assert convert_bytes_to_readable(1610613000) == "1.5GB"

    # Test terabytes
    assert convert_bytes_to_readable(2200000000000) == "2.0TB"

    # Test petabytes
    assert convert_bytes_to_readable(2251799813700000) == "2.0PB"
