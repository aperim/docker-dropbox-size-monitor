# Dropbox Storage Monitor

This script helps you keep track of your Dropbox storage usage and sends alerts via SMS when the usage exceeds defined thresholds. The alerts are sent via the Twilio API. 

It's possible to run the script continuously or just once using an optional parameter. The script can also handle different types of Dropbox tokens, whether they're scoped for a single user or a team. When handling team tokens, the script will impersonate an admin user.

## Setup

First, you need credentials for the relevant services. This includes a `DROPBOX_TOKEN` from Dropbox and credentials (`TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, and `TWILIO_PHONE_NUMBER`) from Twilio.

Then, determine the phone number(s) you wish to send the alerts to, and add them as a comma separated string to the `PHONE_NUMBERS` environment variable.

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

The script checks Dropbox storage usage and sends alerts when the usage has crossed certain thresholds. The storage usage is checked every five minutes.

There are three types of alerts: alert, warning, and critical, which are sent when usage crosses 80%, 90%, and 95% respectively. An alert is only sent once, a warning twice, and a critical alert can be sent every time the storage is checked, up to the maximum number of allowed messages per hour.

Each alert includes the storage level in percentage and the amount of storage used in a human-readable format (KB, MB, GB, etc). A running delta of changes to storage use is also included in the message.

When run in verbose mode, the script will log its progress through each step of the process.

The script will also detect whether the provided Dropbox token is for an individual user or a team. If a team token is used, the script will find and impersonate an admin user for the storage space check.

## Testing

For testing, use pytest:

```bash
pytest tests
```

Note: Due to the reliance on third-party services, full testing requires extensive use of mock objects and is beyond the scope of this guide.

## Questions / Issues

If you have questions or run into problems, open a GitHub issue on this repo.
