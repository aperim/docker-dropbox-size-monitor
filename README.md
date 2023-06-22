# Dropbox Storage Monitor

A script to monitor Dropbox storage size and sends SMS alerts depending on defined level thresholds. This runs as a daemon in the Docker container.

## Running the Docker Container

After cloning the repository, you can use docker-compose to run the image:

```bash
docker-compose up -d
```

You'll need to replace `YOUR_DROPBOX_TOKEN`, `YOUR_TWILIO_ACCOUNT_SID`, `YOUR_TWILIO_AUTH_TOKEN`, `YOUR_TWILIO_PHONE_NUMBER`, and `PHONE_NUMBER_1,PHONE_NUMBER_2` with actual values.

## Environment Variables

Dropbox Token: `DROPBOX_TOKEN`
Twilio Account SID: `TWILIO_ACCOUNT_SID`
Twilio Auth Token: `TWILIO_AUTH_TOKEN`
Twilio Phone Number: `TWILIO_PHONE_NUMBER`
Phone Numbers (comma separated): `PHONE_NUMBERS`
