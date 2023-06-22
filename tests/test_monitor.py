from unittest.mock import Mock, patch
import app.monitor as monitor
import pytest

def test_calculate_dropbox_usage(mocker):
    # Mocking the required responses
    mocker.patch("app.monitor.dbx.users_get_space_usage", return_value=Mock(used=500, allocation=Mock(get_individual=Mock(return_value=Mock(allocated=1000)))))

    assert monitor.calculate_dropbox_usage() == 50

def test_send_alerts(mocker):
    # Mocking the required responses
    # We'll override the phone numbers to avoid sending real messages during testing
    monitor.phone_numbers = ['+9876543210']
    mocker.patch("app.monitor.client.messages.create", return_value=Mock())

    monitor.send_alerts('alert', 10)
    monitor.client.messages.create.assert_called_once_with(body='Dropbox has crossed the alert level of 80%.',
                                                          to='+9876543210',
                                                          from_=monitor.twilio_phone_number)

    monitor.send_alerts('warning', 10)
    monitor.client.messages.create.assert_called_with(body='Dropbox has crossed the warning level of 90%. The rate of increase is 10 per hour.',
                                                      to='+9876543210',
                                                      from_=monitor.twilio_phone_number)

    monitor.send_alerts('critical', 10)
    monitor.client.messages.create.assert_called_with(body='CRITICAL WARNING. Dropbox has crossed the critical level of 95%. The rate of increase is 10 per hour.',
                                                      to='+9876543210',
                                                      from_=monitor.twilio_phone_number)
