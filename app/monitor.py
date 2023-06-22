import os
import argparse
import dropbox
from dropbox.exceptions import AuthError, BadInputError
from twilio.rest import Client
import time
import datetime
import paho.mqtt.client as mqtt
import json
import sys
import base64
import requests
from flask import Flask, request
import threading
import webbrowser

DROPBOX_TOKEN = os.getenv('DROPBOX_TOKEN')
DROPBOX_REFRESH_TOKEN = os.getenv('DROPBOX_REFRESH_TOKEN')
DROPBOX_APP_KEY = os.getenv('DROPBOX_APP_KEY')
DROPBOX_APP_SECRET = os.getenv('DROPBOX_APP_SECRET')
TWILIO_PHONE_NUMBER = os.getenv('TWILIO_PHONE_NUMBER')
TWILIO_ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID')
TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN')
PHONE_NUMBERS = os.getenv('PHONE_NUMBERS').split(',')
ALERT_THRESHOLD = float(os.getenv('ALERT_THRESHOLD', '80'))  # Default value: 80
WARNING_THRESHOLD = float(os.getenv('WARNING_THRESHOLD', '90'))  # Default value: 90
CRITICAL_THRESHOLD = float(os.getenv('CRITICAL_THRESHOLD', '95'))  # Default value: 95
MAX_ALERTS = int(os.getenv('MAX_ALERTS', '10'))  # Default value: 10
LOGGING = int(os.getenv('LOGGING', '0'))  # Default value: 0
MQTT_SERVER = os.getenv('MQTT_SERVER', None)  # MQTT server to use for updates
MQTT_PORT = int(os.getenv('MQTT_PORT', '1883'))  # MQTT port to use for updates
MQTT_TOPIC = os.getenv('MQTT_TOPIC', 'dropbox')  # MQTT topic to publish updates to
MQTT_USERNAME = os.getenv('MQTT_USERNAME', None)
MQTT_PASSWORD = os.getenv('MQTT_PASSWORD', None)

# Variables used for rate limiting and to control number of alerts/warnings sent
hourly_counter = 0
hour_start_time = datetime.datetime.now().hour
alert_sent = 0
warning_sent = 0

# Used for the mqtt client - this work is incomplete
mqtt_client = None

app = Flask(__name__)
redirect_uri = 'http://localhost:5000/oauth2/callback'

@app.route('/oauth2/callback')
def oauth2_callback():
    code = request.args.get('code')
    if code:
        token_url = 'https://api.dropbox.com/oauth2/token'
        auth_header = base64.b64encode(f"{DROPBOX_APP_KEY}:{DROPBOX_APP_SECRET}".encode())
        headers = {
            'Authorization': f"Basic {auth_header.decode()}",
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirect_uri,
        }
        r = requests.post(token_url, data=data, headers=headers)
        if r.status_code == 200:
            token_data = r.json()
            base64_token = base64.b64encode(json.dumps(token_data).encode())
            print(f"Copy and set this in your environment variable:\nDROPBOX_TOKEN={base64_token.decode()}", flush=True)
            os._exit(0)  # Ensure the script stops after printing token
        else:
            return "Error getting tokens.", 400
    else:
        return "No code found in request.", 400

def start_oauth():
    auth_url = f"https://www.dropbox.com/oauth2/authorize?response_type=code&client_id={DROPBOX_APP_KEY}&redirect_uri={redirect_uri}&token_access_type=offline"
    threading.Timer(1, lambda: webbrowser.open_new(auth_url)).start()
    app.run()

def authenticate_dropbox(creds):
    if 'access_token' not in creds or 'refresh_token' not in creds or 'uid' not in creds:
        print("Malformed DROPBOX_TOKEN. Please ensure it's a Base64 encoded string of the token json received from Dropbox.", flush=True)
        os._exit(0)
    
    uid = creds['uid']
    access_token = creds['access_token']
    refresh_token = creds['refresh_token']
    dbx = dropbox.Dropbox(access_token)
    try:
        # This will fail if the token is incorrect, is team scoped, or access token is expired
        dbx.users_get_current_account()
    except BadInputError:
        print("Detected team-scoped token. Proceeding with admin privileges...", flush=True)
        team = dropbox.DropboxTeam(access_token)
        result = team.team_members_list()
        admin_id = [member.profile.team_member_id for member in result.members if member.role.is_team_admin()][0]
        dbx = team.as_user(admin_id)
        return dbx
    except AuthError as e:
        if isinstance(e.error, dropbox.exceptions.ExpiredAccessTokenError):
            print("Access token expired. Refreshing...", flush=True)
            token_url = 'https://api.dropbox.com/oauth2/token'
            auth_header = base64.b64encode(f"{DROPBOX_APP_KEY}:{DROPBOX_APP_SECRET}".encode())
            headers = {
                'Authorization': f"Basic {auth_header.decode()}",
                'Content-Type': 'application/x-www-form-urlencoded',
            }
            data = { 'grant_type': 'refresh_token', 'refresh_token': refresh_token }
            r = requests.post(token_url, data=data, headers=headers)
            if r.status_code == 200:
                token_data = r.json()
                base64_token = base64.b64encode(json.dumps(token_data).encode())
                print(f"Access token refreshed. Copy and set this in your environment variable:\nDROPBOX_TOKEN={base64_token.decode()}", flush=True)
                dbx = dropbox.Dropbox(token_data['access_token'])
                dbx.users_get_current_account()
            else:
                print("Error refreshing token.", flush=True)
                os._exit(0)
        else:
            print("ERROR: Invalid access token. Please re-issue or regenerate your access token.", flush=True)
            os._exit(0)
    except dropbox.exceptions.BadRequestError:
        print(f"Uid {uid} in DROPBOX_TOKEN doesn't match the one in the access token", flush=True)
        os._exit(0)
    return dbx

def authenticate_twilio(account_sid, auth_token):
    """
    Authenticate to Twilio with the provided account SID and auth token.

    :param account_sid: Twilio Account SID.
    :param auth_token: Twilio Auth Token.
    :return: Authenticated Twilio client.
    """
    return Client(account_sid, auth_token)

def convert_bytes_to_readable(bytes_number):
    """
    Convert the given number of bytes to a human-readable format.

    :param bytes_number: The number of bytes.
    :return: A string representing the number of bytes formatted to a legible format.
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB', 'PB']:
        if bytes_number < 1024.0:
            return f"{bytes_number:3.1f}{unit}"
        bytes_number /= 1024.0

def retrieve_storage_info(dropbox_client, verbose):
    """
    Retrieve storage usage data from Dropbox. If verbose is set to True, print the storage information.

    :param dropbox_client: Authenticated Dropbox client.
    :param verbose: Boolean variable denoting whether to print verbose messages.
    :return: Storage usage data from Dropbox.
    """
    if verbose:
        print("Retrieving storage info...", flush=True)
    usage = dropbox_client.users_get_space_usage()
    if usage.allocation.is_individual():
        allocated = usage.allocation.get_individual().allocated
    else:  # team scope
        allocated = usage.allocation.get_team().allocated
    if verbose:
        print(f"Fetched details: Used = {convert_bytes_to_readable(usage.used)}, Allocated = {convert_bytes_to_readable(allocated)}", flush=True)
    return usage

def run_once(dropbox_client, twilio_client, verbose):
    """
    Execute the script once to:
    - Retrieve Dropbox storage usage.
    - Compare usage against thresholds.
    - Send alerts via Twilio if the usage is above thresholds.

    :param dropbox_client: Authenticated Dropbox client.
    :param twilio_client: Authenticated Twilio client.
    :param verbose: Boolean variable signifying whether to print verbose logs.
    :return: None.
    """
    storage_info = retrieve_storage_info(dropbox_client, verbose)
    delta = None
    alert_if_needed(storage_info, delta, twilio_client, verbose)

def run_daemon(dropbox_client, twilio_client, verbose):
    """
    Execute the script in a constant loop to:
    - Continuously, every 5 minutes, retrieve Dropbox storage usage.
    - Compare usage against thresholds.
    - Send alerts via Twilio if the usage is above thresholds.

    :param dropbox_client: Authenticated Dropbox client.
    :param twilio_client: Authenticated Twilio client.
    :param verbose: Boolean variable signifying whether to print verbose logs.
    :return: None.
    """
    prev_storage_info = None
    while True:
        curr_storage_info = retrieve_storage_info(dropbox_client, verbose)
        if prev_storage_info is not None:
            delta = calculate_delta(prev_storage_info, curr_storage_info)
        else:
            delta = None
        prev_storage_info = curr_storage_info
        alert_if_needed(curr_storage_info, delta, twilio_client, verbose)
        time.sleep(300)  # 5 minutes

def calculate_delta(prev_storage_info, curr_storage_info):
    """
    Compute the change in storage usage from the previous check to the current check.

    :param prev_storage_info: Storage usage data from the previous check.
    :param curr_storage_info: Storage usage data from the current check.
    :return: The change in storage usage.
    """
    return curr_storage_info.used - prev_storage_info.used

def send_alert(twilio_client, alert_type, delta_msg, storage_used_readable, usage_pc):
    """
    Send an alert message via the Twilio API.
    
    :param twilio_client: Authenticated Twilio client.
    :param alert_type: String indicating the type of alert.
    :param delta_msg: String detailing the change in storage use from the last check.
    :param storage_used_readable: String denoting the storage usage in a human-readable format.
    :param usage_pc: Float indicating the storage usage in percentage.
    :return: None.
    """
    if alert_type == 'CRITICAL':
        msg_body = f"CRITICAL ALERT: Dropbox storage usage is at {usage_pc}% ({storage_used_readable}).{delta_msg}"
    elif alert_type == 'WARNING':
        msg_body = f"WARNING: Dropbox storage usage is at {usage_pc}% ({storage_used_readable}).{delta_msg}"
    elif alert_type == 'ALERT':
        msg_body = f"ALERT: Dropbox storage usage is at {usage_pc}% ({storage_used_readable}).{delta_msg}"
    else:
        msg_body = f"Dropbox storage usage is at {usage_pc}% ({storage_used_readable}).{delta_msg}"

    for phone_number in PHONE_NUMBERS:
        message = twilio_client.messages.create(
            body=msg_body,
            from_=TWILIO_PHONE_NUMBER,
            to=phone_number
        )
        print(f"Alert sent to {phone_number}.", flush=True)

def alert_if_needed(storage_info, delta, twilio_client, verbose):
    """
    Evaluate the storage usage and send an alert when usage surpasses established thresholds.
    
    :param storage_info: Storage usage data from Dropbox.
    :param delta: The difference in storage use from the previous to the current check.
    :param twilio_client: Authenticated Twilio client.
    :param verbose: Boolean variable denoting whether to print verbose logs.
    :return: None
    """
    global hourly_counter, hour_start_time, alert_sent, warning_sent

    if storage_info.allocation.is_individual():
        allocated = storage_info.allocation.get_individual().allocated
    else: # team scope
        allocated = storage_info.allocation.get_team().allocated

    usage_pc = round((float(storage_info.used) / allocated) * 100, 2)

    storage_used_readable = convert_bytes_to_readable(storage_info.used)

    if verbose:
        print(f"Current storage usage is {usage_pc}% ({storage_used_readable}).", flush=True)

    current_hour = datetime.datetime.now().hour
    if current_hour != hour_start_time:
        hourly_counter = 0
        hour_start_time = current_hour
        alert_sent = 0
        warning_sent = 0

    if hourly_counter >= MAX_ALERTS:
        if verbose:
            print("Maximum number of messages per hour reached. Not sending more alerts this hour.", flush=True)
        return

    delta_msg = f". Storage use change from last check: {delta}" if delta else ""

    # define alert_type variable before checking thresholds
    alert_type = 'OK'

    if usage_pc >= CRITICAL_THRESHOLD:
        if verbose:
            print("Current storage usage exceeds critical threshold. Sending critical alert...", flush=True)
        send_alert(twilio_client, "critical", delta_msg, storage_used_readable, usage_pc)
        alert_type = 'CRITICAL'
        hourly_counter += 1
    elif usage_pc >= WARNING_THRESHOLD:
        if warning_sent < 2:
            if verbose:
                print("Current storage usage exceeds warning threshold. Sending warning...", flush=True)
            send_alert(twilio_client, "warning", delta_msg, storage_used_readable, usage_pc)
            alert_type = 'WARNING'
            hourly_counter += 1
            warning_sent += 1
    elif usage_pc >= ALERT_THRESHOLD:
        if not alert_sent:
            if verbose:
                print("Current storage usage exceeds alert threshold. Sending alert...", flush=True)
            send_alert(twilio_client, "alert", delta_msg, storage_used_readable, usage_pc)
            alert_type = 'ALERT'
            hourly_counter += 1
            alert_sent = 1

    if MQTT_SERVER:
        publish_mqtt_update(usage_pc, storage_info.used, storage_used_readable, allocated, convert_bytes_to_readable(allocated), alert_type, verbose)

def publish_mqtt_update(usage_pc, used_bytes, used_hr, allocation, allocation_hr, state, verbose):
    mqtt_payload = {
        "usagePercentage": usage_pc,
        "usedBytes": used_bytes,
        "usedHumanReadable": used_hr,
        "allocationBytes": allocation,
        "allocationHumanReadable": allocation_hr,
        "state": state,
    }
    result = mqtt_client.publish(f"{MQTT_TOPIC}json", json.dumps(mqtt_payload))
    status = result[0]
    if status == 0:
        if verbose:
            print(f"Send `{json.dumps(mqtt_payload)}` to topic `{MQTT_TOPIC}json`", flush=True)
    else:
        print(f"Failed to send message to topic {MQTT_TOPIC}json", flush=True)
    result = mqtt_client.publish(MQTT_TOPIC, state)
    status = result[0]
    if status == 0:
        if verbose:
            print(f"Send `{state}` to topic `{MQTT_TOPIC}`", flush=True)
    else:
        print(f"Failed to send message to topic {MQTT_TOPIC}", flush=True)


def main():
    global mqtt_client
    parser = argparse.ArgumentParser()
    parser.add_argument("--one-shot", action='store_true', default=False, help='Run the script once and exit')
    parser.add_argument("-v", action='store_true', default=bool(LOGGING), help="Display verbose log output")
    args = parser.parse_args()

    if not DROPBOX_TOKEN:
        print("DROPBOX_TOKEN not found. Starting Dropbox oAuth process...", flush=True)
        start_oauth()
        return
    else:
        try:
            creds = json.loads(base64.b64decode(DROPBOX_TOKEN).decode())
        except Exception as e:
            print("Failed to decode DROPBOX_TOKEN. Ensure it's a Base64 encoded string of the token json received from Dropbox.", flush=True)
            os._exit(0)

    dropbox_client = authenticate_dropbox(creds)
    twilio_client = authenticate_twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

    if MQTT_SERVER:
        mqtt_client = mqtt.Client()

        if MQTT_USERNAME and MQTT_PASSWORD:
            mqtt_client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)

        mqtt_client.connect(MQTT_SERVER, MQTT_PORT)
        mqtt_client.loop_start()

    if args.one_shot:
        run_once(dropbox_client, twilio_client, args.v)
        if MQTT_SERVER:
            mqtt_client.disconnect()
            mqtt_client.loop_stop()
    else:
        try:
            run_daemon(dropbox_client, twilio_client, args.v)
        finally:
            if MQTT_SERVER:
                mqtt_client.disconnect()
                mqtt_client.loop_stop()

if __name__ == '__main__':
    main()