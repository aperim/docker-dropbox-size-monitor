# Dropbox Storage Monitor

This script helps you keep track of your Dropbox storage usage and sends alerts via SMS when the usage exceeds defined thresholds. The alerts are sent via the Twilio API. 

The script can be run continuously or just once using an optional parameter. It can handle different types of Dropbox tokens, whether they're scoped for a single user or a team. When handling team tokens, the script will impersonate an admin user.

The script can also publish MQTT messages that contain information about the current storage usage. These MQTT messages can be handled by various home automation software like Home Assistant.

## Setup

First, you will need credentials for Dropbox and Twilio. This includes a `DROPBOX_TOKEN` from Dropbox and credentials (`TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, and `TWILIO_PHONE_NUMBER`) from Twilio.

Then, determine the phone number(s) you wish to send the alerts to and add them as a comma-separated string to the `PHONE_NUMBERS` environment variable.

If you want to use MQTT messaging, specify your MQTT server with the `MQTT_SERVER` and `MQTT_PORT` environment variables. You can specify the topic with the `MQTT_TOPIC` environment variable.

Next, install the required Python dependencies with:

```bash
pip install -r requirements.txt
```

If you want to use the Docker container:

```bash
docker pull ghcr.io/aperim/docker-dropbox-size-monitor:latest
```

You should then set the environment variables in the docker run command. 

## Environment Variables

The script requires the following environment variables:

* `DROPBOX_TOKEN` - Your Dropbox API token.
* `TWILIO_ACCOUNT_SID` - Your Twilio Account SID.
* `TWILIO_AUTH_TOKEN` - Your Twilio Auth Token.
* `TWILIO_PHONE_NUMBER` - Your Twilio phone number (i.e., the number from which alerts will be sent).
* `PHONE_NUMBERS` - A comma-separated list of phone numbers to send alerts to.
* `ALERT_THRESHOLD` - The storage usage percentage for sending alerts (default is 80%).
* `WARNING_THRESHOLD` - The storage usage percentage for sending warnings (default is 90%).
* `CRITICAL_THRESHOLD` - The storage usage percentage for sending critical alerts (default is 95%).
* `MAX_ALERTS` - The maximum number of messages the script should send in any hour (default is 10).
* `MQTT_SERVER` - The address of the MQTT server to connect to for update messages.
* `MQTT_PORT` - The port of the MQTT server to connect to for update messages (default is 1883).
* `MQTT_TOPIC` - The MQTT topic to post update messages to (default is `dropbox`).

## Usage

You can run the script directly from command line:

```bash
python app/monitor.py
```

For a one-time run:

```bash
python app/monitor.py --one-shot
```

For verbose output:

```bash
python app/monitor.py -v
```

If you're using the Docker container, run it with the needed environment variables:

```bash
docker run --env-file .env ghcr.io/aperim/docker-dropbox-size-monitor:latest
```

Replace `.env` with the path to your environment variables file. For a one-time run, add `--one-shot` at the end. For verbose output, add `-v` at the end.

## About the Script

Every 5 minutes, the script checks your Dropbox storage usage. 

If usage exceeds 80%, 90%, or 95%, the script sends you an SMS alert. An alert is sent once, a warning is sent twice, and a critical alert is sent every time the storage usage is checked, up to the maximum number of allowed alerts per hour.

Every alert includes the storage usage in percentage and the amount of storage used in a human-readable format (KB, MB, GB, etc.). A running delta of the changes to storage usage is also included in the message.

The script also sends MQTT messages with details about the storage usage. Each MQTT message contains the current storage usage in percentage and in bytes, the used and allocated storage in a human-readable format, and the state ('OK', 'ALERT', 'WARNING', 'CRITICAL').

If you run the script in verbose mode, it logs its progress for each step.

## Testing

For testing, use pytest:

```bash
pytest tests
```

Note: Due to the reliance on third-party services, full testing requires extensive use of mock objects and is beyond the scope of this guide.

## Questions / Issues

If you have questions or run into problems, open a GitHub issue on this repo.
