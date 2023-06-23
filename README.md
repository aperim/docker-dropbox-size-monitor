# Dropbox Storage Monitor

This script helps you keep track of your Dropbox storage usage and sends alerts via SMS when the usage exceeds defined thresholds. The alerts are sent via the Twilio API. 

The script can be run continuously or just once using an optional parameter. It can handle different types of Dropbox tokens, whether they're scoped for a single user or a team. When handling team tokens, the script will impersonate an admin user. Additionally, the script supports OAuth 2.0 and automatic token refreshing.

The script can also publish MQTT messages that contain information about the current storage usage. These MQTT messages can be handled by various home automation software like Home Assistant.

## Setup

As the script relies on a Dropbox OAuth 2 flow, an initial setup is required to obtain a token. The script will automatically initiate this process if it doesn't find a `DROPBOX_TOKEN` environment variable. 

Upon initiation, the script starts a local server and opens a new tab in your default web browser where you order to approve its access to your Dropbox account. After you approve the access, the script retrieves the access and refresh tokens from Dropbox, Base64 encodes the token JSON, and outputs it for you to copy. This token must be stored as `DROPBOX_TOKEN` in your environment variables.

In general, handle the `DROPBOX_TOKEN` securely as it allows access to your Dropbox account. Also ensure to keep the `DROPBOX_APP_KEY` and `DROPBOX_APP_SECRET` confidential to prevent misuse.

The detailed steps to setup and run the script locally or using Docker are as follows:

### Running Locally

For running the script locally, first install the dependencies. In your terminal, navigate to the directory of the script and install the dependencies using pip:

```bash
pip install -r requirements.txt
```

Then, run the script:

```bash
python app/monitor.py
```

When you run the script for the first time, a URL opens in your web browser. Approve the script’s access to your Dropbox account. Post approval, Dropbox redirects you back to a page served by a local server started by this script. The console where you run the script will display the access and refresh tokens. Encode this JSON string in Base64 and store it in the `DROPBOX_TOKEN` environment variable.

### Using Docker

If you are using Docker, pull the Docker image first:

```bash
docker pull ghcr.io/aperim/docker-dropbox-size-monitor:latest
```

Then run the script using Docker:

```bash
docker run -p 5000:5000 --env-file .env ghcr.io/aperim/docker-dropbox-size-monitor:latest
```

Similar to running the script locally, you will see a URL in your web browser. Upon approving the script's access to your Dropbox, you will be redirected to a local server page. The tokens will be printed on the console where you ran the Docker command.

### Validating Container Signature

The `latest` container will be signed. Use the public key below to verify.

```text
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsXVH35nPvwu15V3Vs7oj4pCO6xuC
+1nInXhTUuySGotaLD1vDpxEU1w1RsbJ1LqFkd1gSUzMoaYSFl5BVZzomw==
-----END PUBLIC KEY-----
```

## Environment Variables

The script requires the following environment variables:

* `DROPBOX_TOKEN` - Your Dropbox API token as a Base64 encoded JSON string.
* `DROPBOX_APP_KEY` - Your Dropbox App Key.
* `DROPBOX_APP_SECRET` - Your Dropbox App Secret.
* `TWILIO_ACCOUNT_SID` - Your Twilio Account SID.
* `TWILIO_AUTH_TOKEN` - Your Twilio Auth Token.
* `TWILIO_PHONE_NUMBER` - Your Twilio phone number (i.e., the number from which alerts will be sent).
* `PHONE_NUMBERS` - A comma-separated list of phone numbers to send alerts to.
* `ALERT_THRESHOLD` - The storage usage percentage for sending alerts (default is 80%).
* `WARNING_THRESHOLD` - The storage usage percentage for sending warnings (default is 90%).
* `CRITICAL_THRESHOLD` - The storage usage percentage for sending critical alerts (default is 95%).
* `MAX_ALERTS` - The maximum number of messages the script should send in any hour (default is 10).
* `MQTT_SERVER` - The address of the MQTT server to connect to for update messages (if using MQTT).
* `MQTT_PORT` - The port of the MQTT server to connect to for update messages (default is 1883; only needed if using MQTT).
* `MQTT_TOPIC` - The MQTT topic to post update messages to (default is `dropbox`; only needed if using MQTT).


## Usage

Once the `DROPBOX_TOKEN` is set up, run the script:

```bash
python app/monitor.py
```

The script can also perform a one-time run or verbose output:

```bash
python app/monitor.py --one-shot  # For a one-time run
python app/monitor.py -v  # For verbose output
```

With Docker, you may use:

```bash
docker run --env-file .env ghcr.io/aperim/docker-dropbox-size-monitor:latest
docker run -p 5000:5000 --env-file .env ghcr.io/aperim/docker-dropbox-size-monitor:latest --one-shot  # For a one-time run
docker run -p 5000:5000 --env-file .env ghcr.io/aperim/docker-dropbox-size-monitor:latest -v  # For verbose output
```

Replace `.env` with the path to your environment variables file.

## About the script

Every 5 minutes, the script checks Dropbox storage usage. If usage exceeds 80%, 90%, or 95%, it sends an SMS alert. The type of alert is "alert,""warning," or "critical" for exceeding 80%, 90%, or 95%, respectively. 

Every alert includes the storage usage in percentage and in a human-readable format (KB, MB, GB, etc.), with a running delta of the changes. The script uses MQTT messages to provide details about the storage usage. It sends them in a dictionary with keys: the current storage usage in percentage and bytes, used and allocated storage in a human-readable format, and the state (OK, ALERT, WARNING, CRITICAL). 

Running the script in verbose mode logs all steps.

## Testing

For testing, use pytest:

```bash
pytest tests
```

Note: Due to the reliance on third-party services, full testing requires extensive use of mock objects and is beyond the scope of this guide.

## Questions / Issues

If you have questions or run into problems, open a GitHub issue on this repo.
