import os
import pytest

# Set the below dummy environment values only if corresponding ones aren't already set
os.environ.setdefault('PHONE_NUMBERS', '1234567890')
os.environ.setdefault('TWILIO_PHONE_NUMBER', '1234567890')
os.environ.setdefault('TWILIO_ACCOUNT_SID', 'test_sid')
os.environ.setdefault('TWILIO_AUTH_TOKEN', 'test_token')
os.environ.setdefault('DROPBOX_TOKEN', 'test_dropbox_token')

# Import the monitored module refreshingly after setting environment variables
import app.monitor

def test_convert_bytes_to_readable():
    """Test convert_bytes_to_readable function."""

    # Test bytes with no units
    assert app.monitor.convert_bytes_to_readable(500) == "500.0B"

    # Test kilobytes
    assert app.monitor.convert_bytes_to_readable(1500) == "1.5KB"

    # Test megabytes
    assert app.monitor.convert_bytes_to_readable(1049000) == "1.0MB"

    # Test gigabytes
    assert app.monitor.convert_bytes_to_readable(1610613000) == "1.5GB"

    # Test terabytes
    assert app.monitor.convert_bytes_to_readable(2200000000000) == "2.0TB"

    # Test petabytes
    assert app.monitor.convert_bytes_to_readable(2251799813700000) == "2.0PB"
